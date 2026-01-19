#include "ssl_client.hpp"
#include "packets_shared.hpp"
#include <iostream>

class Client : public SSLClient
{
public:
	Client(asio::io_context& io_context, asio::ssl::context& context, const asio::ip::tcp::resolver::results_type& endpoints);

	virtual void OnConnect();
    virtual void OnHandshake();
	virtual void OnError(std::error_code errc);
    virtual bool OnReceive(IPacket* pPacket);
};

Client::Client(asio::io_context& io_context, asio::ssl::context& context, const asio::ip::tcp::resolver::results_type& endpoints) :
	SSLClient(io_context, context, endpoints)
{
}

void Client::OnConnect()
{
	printf("OnConnect\n");
}

void Client::OnHandshake()
{
    printf("OnHandshake\n");

    PACKET( ChainFileRequest, c );
    Write( c );
}

void Client::OnError(std::error_code errc)
{

	printf("OnError - %s\n", errc.message().c_str());
}

bool Client::OnReceive(IPacket* pPacket)
{
    //printf("OnReceive\n");

    return true;
}

const char m_szClientCertificate[1312] = R"(
-----BEGIN CERTIFICATE-----
MIICrjCCAZYCFCIHyBwueiCZ4jVHMxOgsxQb/M2iMA0GCSqGSIb3DQEBCwUAMBMx
ETAPBgNVBAMMCE15Um9vdENBMB4XDTI0MDkyNDA0MjcxOFoXDTI1MDkyNDA0Mjcx
OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA7mAr9MZsAazHHPZqyrcAyf10IK9X9CKpqh9gpiwJ8v9uQ14U3eug
OIHDiQEJ0lSsy4mF+I0gIuQgbT+0ISJ3vBDqrCT6XQ9ZD7KRnC7bCZ/LWaw2txQl
nggg52UlWdKXnRS9IRFdeFqZYeZpAiyTjKe9CePEDION7wgF8vIAYXkrRpU4i0oy
9C4iyPX8MIXHOWEGBZXmJVB4ZzHiy8k+t9ldX5nPmHf8eoBR4o5+83iRv2zKSkGw
07OBWCMFZphDjlOogrkvqh3vpEY5ETw5HROVJmHaWwfaKWRTTgfM4v49KXMDk/sO
m7BTi9FF+mpO6N+7OSbsdTfTXjeh/7JdjwIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQBytpdS9zXjKnkycOdTEavyWXiDND0fWm9UfvW5HGzMcLsN4HkLPkkf5TwdRiBG
VB3xfjB+Di/9HSXOcZyqUweXMy7v1pBYK9vWbycDxm+jSIfZvIoqgzbe5XkTnR8l
YkZBT4aEGv9Be3LK48MWA2VLK217Nnc+Z75fbyxWcTZgwLKO4qHMiTZLRLFdSykt
nlNogV3B182C1juQil6Caw0kAaWBwPR39IAb6NZhkRouIKPfGVBoDoQCKGHQBCeb
upHOPbmxWjXaokcz/mOpFYPe+j17AOEh9luJiF/+JTGSkUd1F4jhPDZpfQmA8wsV
gbQnuEBj6b/LUPaByfSjidbx
-----END CERTIFICATE-----
)";
const char m_szClientPrivateKey[1706] = R"(
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDuYCv0xmwBrMcc
9mrKtwDJ/XQgr1f0IqmqH2CmLAny/25DXhTd66A4gcOJAQnSVKzLiYX4jSAi5CBt
P7QhIne8EOqsJPpdD1kPspGcLtsJn8tZrDa3FCWeCCDnZSVZ0pedFL0hEV14Wplh
5mkCLJOMp70J48QMg43vCAXy8gBheStGlTiLSjL0LiLI9fwwhcc5YQYFleYlUHhn
MeLLyT632V1fmc+Yd/x6gFHijn7zeJG/bMpKQbDTs4FYIwVmmEOOU6iCuS+qHe+k
RjkRPDkdE5UmYdpbB9opZFNOB8zi/j0pcwOT+w6bsFOL0UX6ak7o37s5Jux1N9Ne
N6H/sl2PAgMBAAECggEAAtCz9DIbuHFX8KmgXUCIC9qocnJfsYxvQIkaVRwUCgCm
Rrlnua88ty4hJw8SFJ/XYpf/Mw5HoOHc2C12bSXBEEGK4/mT02GJBbxwJ84N3DE8
75QvGT5tq04hRVpWdJceH0bNbQSNfAxl31gfSV1JaNHaU7GS8SrklDweBd6BzqTf
3aAsKzLZRlC6OPKNB7OBqMgIAYhGcNvUywgswhHkJxFlsVTz9Z5O/jhEX4QZioaT
Py6o4jx5bUn4yk96z7adR+CmbChlpvW0PvRdJtqegvdCt5eroAS0quUCCkOGcNwC
x5vnzJHC7LMuGRNfkepqN8/YybD9thDtfP1OpqiYgQKBgQD9/uL6PcnEUNyROQyZ
VBtHY5kbZp1ZJY35l+ZKaYy/hgMimu/pF2AdAuFdkwEGeMUZNgmsTapZyGqiEG6A
A8iu5KndGXPiLNjJLmXjTTaxYVJd1dmRkahwBVAb/eBROEt7iiPkbZhnbtjOPJE+
442st3ek+q8KJKgVLvwees5vLwKBgQDwQbrpLWnI4NZaGpITZdSM+Ef8oDNu20mO
ZnVW0H3pYPO+06oigv018ueF6YaBiI3XNhG7IIZAoaTLV33oN1eFSRt5HkAS1COt
MDeeILUJhj+qy3FkAtBN1CUbHAok4h1ggfn77vb/AHyhq1+Q6ovi8eGask2+59VZ
AKoaWiRfoQKBgE2wvyCn8aVYzn6lIpNrxIRLlLNq6cow0IJ90fUE4AZdKWxWU/fK
LJ3zGZgTtQaTvkX932uSvf6EbQlxWTtS7PmB++sjM+0EprKyvHuQTKBpEladaNU7
5neNSHmnaAuv2nbJRD1EwI8yuqIqqIrB873WyIPwIcZKfBcurfNswOQFAoGBAI8/
cZUD2bXGsKdKflwIdAGVKz6pueDX6HR6DG41o00Z3Fqj0yX+mcCn0nkacnMbGw79
EvdSfhldB2eiA9UH4iv7GeFOMv/G8nqZbB/g+m/yVlWcNUBfGRm+al1Oi5HQK5nW
BVm78hK6lJTEHBfIcJ1ggJX+x7ISgjct2T4bDuLhAoGAaHbBcyL0mqMRHibJeiZq
ZC6jN8BVOO69MeQ9GrUz7uFTvoCTd5rM2Sq6yEFp9HPH57pIIw1WXIpd81gMaV1C
0fjgZRrPdWNtoV+PacvHgEsBjbL1E57gTc334upSdFRaUlrXpEdBA8E7WiuQ3/IV
5HpZ03ydNe7Nfe10l38RjdE=
-----END PRIVATE KEY-----
)";

#include <random>

int main()
{
    try
    {
        asio::io_context io_context;

        asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve("localhost", "8080");

        asio::ssl::context context( asio::ssl::context::tlsv12 );

        context.use_certificate(asio::buffer(m_szClientCertificate), asio::ssl::context_base::pem);
        context.use_private_key(asio::buffer(m_szClientPrivateKey), asio::ssl::context_base::pem);

        context.set_verify_mode(asio::ssl::context::default_workarounds |
            asio::ssl::context::no_sslv2 |
            asio::ssl::context::no_sslv3);

        std::shared_ptr<Client> client = std::make_shared<Client>(io_context, context, endpoints);

        std::thread t([&io_context]() { io_context.run(); });

        t.join();
    }
    catch (std::exception& e)
    {
    //    std::cerr << "Exception: " << e.what() << "\n";
    }

    getchar();
}
