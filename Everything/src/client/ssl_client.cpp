#include "ssl_client.hpp"
#include <iostream>

SSLClient::SSLClient(asio::io_context& io_context, asio::ssl::context& context, const asio::ip::tcp::resolver::results_type& endpoints) : 
    m_Context(io_context),
    m_Socket(io_context, context)
{
    m_Socket.set_verify_mode(asio::ssl::verify_peer);
    m_Socket.set_verify_callback(
        std::bind(&SSLClient::VerifyCertificate, this, std::placeholders::_1, std::placeholders::_2));

    Connect(endpoints);
}

SSLClient::~SSLClient()
{
    Close();
}

void SSLClient::Close()
{
    m_Socket.shutdown();
}

void SSLClient::Write(std::shared_ptr<IPacket> pPacket)
{
    if (pPacket.get() && !pPacket->GetHeader())
    {
        return;
    }

    bool bWriting = !m_Queue.empty();

    m_Queue.emplace_back(std::move(pPacket));

    if (!bWriting)
    {
        R_Write();
    }
}

bool SSLClient::VerifyCertificate(bool preverified, asio::ssl::verify_context& ctx)
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

    return true;
}

void SSLClient::Connect(const asio::ip::tcp::resolver::results_type& endpoints)
{
    asio::async_connect(m_Socket.lowest_layer(), endpoints,
        [this](const std::error_code& error,
            const asio::ip::tcp::endpoint& /*endpoint*/)
        {
            if (!error)
            {
                Handshake();
            }
            else
            {
                OnError( error );
                Close();
            }
        });
}

void SSLClient::Handshake()
{
    m_Socket.async_handshake(asio::ssl::stream_base::client,
        [this](const std::error_code& error)
        {
            if (!error)
            {
                OnHandshake();
                R_ReadHeader();
            }
            else
            {
                OnError( error );
                Close();
            }
        });
}

void SSLClient::R_Write()
{
    std::shared_ptr<IPacket>& pPacket = m_Queue.front();

    pPacket->GetHeader()->CalculateCRC();

    asio::async_write(m_Socket,
        asio::buffer(pPacket->GetHeader(), pPacket->GetPacketSize()),
        [this](std::error_code errc, std::size_t /*length*/)
        {
            if (!errc)
            {
                m_Queue.pop_front();

                if (!m_Queue.empty())
                {
                    R_Write();
                }
            }
            else
            {
                OnError( errc );
                Close();
            }
        });
}

void SSLClient::R_ReadHeader()
{
    asio::async_read(m_Socket,
        asio::buffer(m_Buf, MAX_HEADER_SIZE),
        [this](std::error_code errc, std::size_t length)
        {
            Header_t* pHeader = (Header_t*)m_Buf;

            if (!errc)
            {
                if (length == MAX_HEADER_SIZE && pHeader && pHeader->IsValid())
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
                OnError(errc);
                Close();
            }
        });
}

void SSLClient::R_ReadFooter()
{
    Header_t* pHeader = (Header_t*)m_Buf;

    asio::async_read(m_Socket,
        asio::buffer(&m_Buf[0] + MAX_HEADER_SIZE, pHeader->GetPacketLength() - MAX_HEADER_SIZE),
        [this](std::error_code errc, std::size_t length)
        {
            Header_t* pPacket = (Header_t*)m_Buf;

            if (!errc)
            {
                if (length == (pPacket->GetPacketLength() - MAX_HEADER_SIZE) && pPacket->ValidateCRC())
                {
                    auto spPacket = IPacket::Create(pPacket->GetPacketID());

                    spPacket->Set( pPacket );

                    if (spPacket)
                    {
                        if (OnReceive(spPacket.get()))
                        {
                            spPacket->Process();
                        }
                    }
                    else
                    {
                        static CCustomErrorCategory ec("R_ReadFooter", "Unknown packet!!, id: %i", pPacket->GetPacketID());
                        errc = std::error_code(777, ec);
                    }

                    R_ReadHeader();
                }
                else
                {
                    static CCustomErrorCategory ec("R_ReadFooter", "R_ReadFooter - %s",
                        length != (pPacket->GetPacketLength() - MAX_HEADER_SIZE) ? "Invalid Header Length" : "Invalid CRC32");
                    errc = std::error_code(777, ec);
                }
            }

            if (errc)
            {
                OnError(errc);
                Close();
            }
        });
}
