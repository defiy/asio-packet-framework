#include "ssl_server.hpp"
#include "ssl_session.hpp"
#include "packets_shared.hpp"

SSLSession::SSLSession(asio::ssl::stream<asio::ip::tcp::socket> socket)
	: m_Socket(std::move(socket))
{
    m_Socket.set_verify_mode(asio::ssl::verify_peer);
    m_Socket.set_verify_callback(
        std::bind(&SSLSession::VerifyCertificate, this, std::placeholders::_1, std::placeholders::_2));

    m_bVerified = false;
}

bool SSLSession::VerifyCertificate(bool preverified, asio::ssl::verify_context& ctx)
{
    // The verify callback can be used to check whether the certificate that is
    // being presented is valid for the peer. For example, RFC 2818 describes
    // the steps involved in doing this for HTTPS. Consult the OpenSSL
    // documentation for more details. Note that the callback is called once
    // for each certificate in the certificate chain, starting from the root
    // certificate authority.

    // In this example we will simply print the certificate's subject name.
    // Get the current certificate
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    printf("Verifying %s\n", subject_name);

    return m_pServer->VerifyCertificate( this, preverified, ctx );
}

SSLSession::~SSLSession()
{
    //Close();
}

void SSLSession::Start(SSLServer* pServer)
{
    m_pServer = pServer;

    Handshake();
}

void SSLSession::Close()
{
    std::error_code ec;
    m_Socket.shutdown( ec );

    if ( ec )
    {
        m_pServer->OnError( this, ec );
    }

    m_pServer->RemoveSession( shared_from_this() );
}

void SSLSession::Write(std::shared_ptr<IPacket> pPacket)
{
    if (!pPacket && !pPacket->GetHeader())
    {
        return;
    }

    bool bWriting = !m_Queue.empty();

    m_Queue.emplace_back( std::move(pPacket) );

    if ( !bWriting )
    {
        R_Write();
    }
}

void SSLSession::WriteFile(const char* pFileName, std::shared_ptr<IPacket> pStreamPacket)
{
    std::vector<Byte> buf;
    if ( !UTIL_ReadFile(pFileName, buf) )
    {
        printf("[-] Couldn't read file to write it\n");
        return;
    }

    Stream( buf, pStreamPacket );
}

void SSLSession::Stream(std::vector<Byte>& buf, std::shared_ptr<IPacket> pStreamPacket)
{
    if (buf.empty())
    {
        printf("[-] Trying to write empty file\n");
        return;
    }

    Stream( buf.data(), buf.size(), pStreamPacket );
}

void SSLSession::Stream(Byte* buf, size_t size, std::shared_ptr<IPacket> streamPacket)
{
    _StreamPacket_t* pStream = (_StreamPacket_t*) streamPacket->GetHeader();

    const size_t chunkSize = sizeof( pStream->m_StreamBuf );

    size_t totalSize = size;
    size_t bytesSent = 0;

    bool bFirstWrite = true;

    while (bytesSent < totalSize)
    {
        size_t remainingBytes = totalSize - bytesSent;
        size_t currentChunkSize = std::min(chunkSize, remainingBytes);

        pStream->m_bClear = bFirstWrite;
        pStream->m_bTrailing = false;
        memcpy( pStream->m_StreamBuf, buf + bytesSent, currentChunkSize );

        if (currentChunkSize < chunkSize)
        {
            int r = chunkSize - currentChunkSize;
            memset( pStream->m_StreamBuf + currentChunkSize, 0, r );
        }

        bytesSent += currentChunkSize;
        bFirstWrite = false;

        if (bytesSent >= totalSize)
        {
            pStream->m_bTrailing = true;
        }

        pStream->m_Length = currentChunkSize;

        Write( streamPacket );

        if (bytesSent < totalSize)
        {
            streamPacket = streamPacket->Create( streamPacket->GetHeader()->GetPacketID() );
            pStream = (_StreamPacket_t*) streamPacket->GetHeader();
        }
    }
}

void SSLSession::Handshake()
{
    auto self(shared_from_this());

    m_Socket.async_handshake(asio::ssl::stream_base::server,
        [this, self](const std::error_code& error)
        {
            if (!error)
            {
                m_pServer->OnHandshake( self.get() );
                R_ReadHeader();
            }
            else
            {
                m_pServer->OnError( self.get(), error);
                m_pServer->RemoveSession( self );
            }
        });
}

void SSLSession::R_Write()
{
    auto self(shared_from_this());

    auto& pPacket = m_Queue.front();

    pPacket->GetHeader()->CalculateCRC();

    asio::async_write(m_Socket,
        asio::buffer( pPacket->GetHeader(), pPacket->GetPacketSize() ),
        [this, self](std::error_code errc, std::size_t length)
        {
            if ( !errc )
            {
                m_Queue.pop_front();

                if (!m_Queue.empty())
                {
                    R_Write();
                }
            }
            else
            {
                m_pServer->OnError( self.get(), errc );
                m_pServer->RemoveSession( self );
            }
        });
}

void SSLSession::R_ReadHeader()
{
    auto self(shared_from_this());

    asio::async_read(m_Socket,
        asio::buffer( m_Buf, MAX_HEADER_SIZE ),
        [this, self](std::error_code errc, std::size_t length)
        {
            Header_t* pHeader = (Header_t*)m_Buf;

            if (!errc)
            {
                if ( !errc && length == MAX_HEADER_SIZE && pHeader && pHeader->IsValid() )
                {
                    R_ReadFooter();
                }
                else
                {
                    static CCustomErrorCategory ec("R_ReadHeader", "R_ReadHeader - %s",
                        length != MAX_HEADER_SIZE ? "Invalid Header Length" : "Invalid Header");
                    errc = std::error_code(777, ec);
                }
            }

            if (errc)
            {
                m_pServer->OnError( self.get(), errc );
                m_pServer->RemoveSession( self );
            }
        });
}

void SSLSession::R_ReadFooter()
{
    auto self(shared_from_this());

    Header_t* pHeader = (Header_t*)m_Buf;

    asio::async_read(m_Socket,
        asio::buffer( &m_Buf[ 0 ] + MAX_HEADER_SIZE, pHeader->GetPacketLength() - MAX_HEADER_SIZE ),
        [this, self](std::error_code errc, std::size_t length)
        {
            Header_t* pPacket = (Header_t*)m_Buf;

            if ( !errc )
            {
                if (length == (pPacket->GetPacketLength() - MAX_HEADER_SIZE) && pPacket->ValidateCRC())
                {
                    auto spPacket = IPacket::Create( pPacket->GetPacketID() );

                    spPacket->Set( pPacket );
                    spPacket->SetSession( self.get() );

                    if (spPacket)
                    {
                        if (m_pServer->OnReceive(self.get(), spPacket.get()))
                        {
                            spPacket->Process();
                        }
                    }
                    else
                    {
                        static CCustomErrorCategory ec("R_ReadFooter", "Unknown packet!!, id: %i", pPacket->GetPacketID());
                        errc = std::error_code( 777, ec );
                    }

                    R_ReadHeader();
                }
                else
                {
                    static CCustomErrorCategory ec("R_ReadFooter", "R_ReadFooter - %s",
                        length != (pPacket->GetPacketLength() - MAX_HEADER_SIZE) ? "Invalid Header Length" : "Invalid CRC32");
                    errc = std::error_code( 777, ec );
                }
            }

            if (errc)
            {
                m_pServer->OnError(self.get(), errc);
                m_pServer->RemoveSession(self);
            }
        });
}
