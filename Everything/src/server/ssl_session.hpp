#ifndef SSL_SESSION_HPP
#define SSL_SESSION_HPP

#include <memory>
#include <deque>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include "packet.hpp"

class SSLServer;
struct StreamPacket;

class SSLSession : public std::enable_shared_from_this<SSLSession>
{
public:
	SSLSession(asio::ssl::stream<asio::ip::tcp::socket> socket);
	~SSLSession();

	void Start(SSLServer* pServer);
	void Close();

	void Write(std::shared_ptr<IPacket> pPacket);

	// pStreamPacket -> STREAM_PACKET only
	void WriteFile(const char* pFileName, std::shared_ptr<IPacket> pStreamPacket);
	void Stream(std::vector<Byte>& buf, std::shared_ptr<IPacket> pStreamPacket);
	void Stream(Byte* buf, size_t size, std::shared_ptr<IPacket> pStreamPacket);

	bool VerifyCertificate(bool preverified, asio::ssl::verify_context& ctx);

	SSLServer* GetServer();

private:
	void Handshake();

	void R_Write();
	void R_ReadHeader();
	void R_ReadFooter();

private:
	asio::ssl::stream<asio::ip::tcp::socket> m_Socket;
	std::deque<std::shared_ptr<IPacket>> m_Queue;

	// Header_t m_HeaderBuf;
	// Byte m_HeaderBuf[ MAX_HEADER_SIZE ];
	// Byte m_PacketBuf[ MAX_PACKET_LENGTH ];

	Byte m_Buf[ MAX_PACKET_SIZE ];

	SSLServer* m_pServer;

public:
	bool m_bVerified;
};

inline SSLServer* SSLSession::GetServer()
{
	return m_pServer;
}

#endif // !SSL_SESSION_HPP
