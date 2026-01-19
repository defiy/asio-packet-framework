#include <iostream>
#include "ssl_server.hpp"
#include "packets_shared.hpp"

class Server : public SSLServer
{
public:
    Server(asio::io_context& io_context, unsigned short port);

    virtual bool VerifyCertificate(SSLSession* pSession, bool preverified, asio::ssl::verify_context& ctx);

    virtual void OnConnect(SSLSession* pSession);
    virtual void OnHandshake(SSLSession* pSession);
    virtual void OnError(SSLSession* pSession, std::error_code errc);
    virtual bool OnReceive(SSLSession* pSession, IPacket* pPacket);
};

Server::Server(asio::io_context& io_context, unsigned short port) :
    SSLServer(io_context, port)
{
}

bool Server::VerifyCertificate(SSLSession* pSession, bool preverified, asio::ssl::verify_context& ctx)
{
    pSession->m_bVerified = true;

    return pSession->m_bVerified;
}

void Server::OnConnect(SSLSession* pSession)
{
    printf("OnConnect\n");
}

void Server::OnHandshake(SSLSession* pSession)
{
    printf("OnHandshake\n");

    //PACKET( CertificateStream, t );

    //pSession->WriteFile( "resource/w2", t );
}

void Server::OnError(SSLSession* pSession, std::error_code errc)
{
    printf("OnError - %s\n", errc.message().c_str());
}

bool Server::OnReceive(SSLSession* pSession, IPacket* pPacket)
{
    printf("OnReceive\n");

    return true;
}

int main()
{
    try
    {
        //ByteVector vec;
        //if (!UTIL_ReadFile("resource/test_file.txt", vec))
        //{
        //    printf("[-] Couldn't read file!\n");
        //}
        //else
        //{
        //    for (const auto& c : vec)
        //    {
        //        printf("%c", c);
        //    }
        //}

        asio::io_context io_context;

        std::shared_ptr<SSLServer> server = std::make_shared<Server>(io_context, 8080);

        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}
