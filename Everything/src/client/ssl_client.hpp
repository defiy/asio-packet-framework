#ifndef SSL_CLIENT_HPP
#define SSL_CLIENT_HPP

#include <deque>
#include <memory>
#include <asio/ssl.hpp>
#include <asio.hpp>
#include "packet.hpp"

class SSLClient
{
public:
	SSLClient(asio::io_context& io_context, asio::ssl::context& context, const asio::ip::tcp::resolver::results_type& endpoints);
	~SSLClient();

	void Close();

	void Write(std::shared_ptr<IPacket> pPacket);

	virtual void OnConnect() = 0;
	virtual void OnHandshake() = 0;
	virtual void OnError(std::error_code errc) = 0;

	virtual bool OnReceive(IPacket* pPacket) = 0;	// Called before the packet is processed
													// return true to process the packet

private:
	bool VerifyCertificate(bool preverified, asio::ssl::verify_context& ctx);

	void Connect(const asio::ip::tcp::resolver::results_type& endpoints);
	void Handshake();

	void R_Write();
	void R_ReadHeader();
	void R_ReadFooter();

private:
	asio::io_context& m_Context;
	asio::ssl::stream<asio::ip::tcp::socket> m_Socket;
	std::deque<std::shared_ptr<IPacket>> m_Queue;

	// Header_t m_HeaderBuf;
	// Byte m_HeaderBuf[ MAX_HEADER_SIZE ];
	// Byte m_PacketBuf[ MAX_PACKET_LENGTH ];

	Byte m_Buf[MAX_PACKET_SIZE];

private:
};

#endif // !SSL_CLIENT_HPP
