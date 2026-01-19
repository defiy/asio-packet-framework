#include "ssl_server.hpp"

SSLServer::SSLServer(asio::io_context& io_context, unsigned short port) :
    m_Acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
    m_Context( asio::ssl::context::tlsv12 ),
    m_nPort(port)
{
    m_Context.use_certificate(asio::buffer( m_szServerCertificate ), asio::ssl::context_base::pem);
    m_Context.use_private_key(asio::buffer( m_szServerPrivateKey ), asio::ssl::context::pem);

    m_Context.set_options(asio::ssl::context::default_workarounds |
        asio::ssl::context::no_sslv2 |
        asio::ssl::context::no_sslv3);

    //m_Context.set_verify_callback()

    R_Accept();
}

void SSLServer::Multicast(std::shared_ptr<IPacket> pPacket, SSLSession* pIgnore)
{
    for (const auto& pClient : m_Sessions)
    {
        if (pIgnore == pClient.get())
            continue;

        pClient->Write( pPacket );
    }
}

void SSLServer::RemoveSession(std::shared_ptr<SSLSession> pSession)
{
    if (m_Sessions.contains( pSession ))
    {
        m_Sessions.erase( pSession );
    }
}

bool SSLServer::VerifyCertificate(SSLSession* pSession, bool preverified, asio::ssl::verify_context& ctx)
{
    return preverified;
}

void SSLServer::R_Accept()
{
    m_Acceptor.async_accept(
        [this](const std::error_code& error, asio::ip::tcp::socket socket)
        {
            if ( !error )
            {
                auto pSession = std::make_shared<SSLSession>( asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket), m_Context) );
                
                pSession->Start( this );

                m_Sessions.insert( pSession );

                OnConnect( pSession.get() );
            }

            R_Accept();
        });
}
