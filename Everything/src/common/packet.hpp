#ifndef PACKET_HPP
#define PACKET_HPP

#include <unordered_map>
#include <memory>
#include "platform.hpp"
#include "utilities.hpp"
#include <string.h>
#include "Crc32.h"

#define MAX_PACKET_SIZE 0x1000
#define PACKET_HEADER 0x70707070

#define MAX_HEADER_SIZE sizeof( Header_t )
#define MAX_PACKET_LENGTH MAX_PACKET_SIZE - MAX_HEADER_SIZE

#define PACKET( p, v ) auto v = std::make_shared<p>()

typedef UInt32 PacketID_t;

struct Packet_t;
class IPacket;
class SSLSession;

using createfunc_t = std::shared_ptr<IPacket>(*)();

// static inline std::unordered_map<PacketID_t, createfunc_t> s_PacketHash;
// have to do it this way
//
inline std::unordered_map<PacketID_t, createfunc_t>& GetPacketHash() {
	static std::unordered_map<PacketID_t, createfunc_t> s_PacketHash;
	return s_PacketHash;
}

struct Header_t
{
	Header_t(UInt32 header, PacketID_t id, UInt32 length);

	bool		IsValid();

	void		CalculateCRC();
	bool		ValidateCRC();
	void		ResetCRC();

	UInt32		GetPacketHeader();
	PacketID_t	GetPacketID();
	UInt32		GetPacketCRC();
	UInt32		GetPacketLength();

	void		SetPacketHeader(UInt32 header);
	void		SetPacketID(PacketID_t packetID);
	void		SetPacketCRC(UInt32 crc);
	void		SetPacketLength(UInt32 length);

private:
	UInt32		m_uiHeader;
	PacketID_t	m_PacketID;
	UInt32		m_uiCRC32;
	UInt32		m_uiLength;

	friend class IPacket;
	friend class Packet_t;
};

class IPacket
{
public:
	virtual void		Process() = 0;

	virtual size_t		GetPacketSize() = 0;
	virtual Header_t*	GetHeader() = 0;

	// Moves, no copies
	virtual void		Set(void* pSet) = 0;
	void Copy(IPacket* pPacket);
	static std::shared_ptr<IPacket> Create(PacketID_t packetID);

#ifdef _SERVER
	void SetSession(SSLSession* pSession);
	SSLSession* GetSession();
#endif // _SERVER

private:
#ifdef _SERVER
	SSLSession* m_pSession;
#endif // _SERVER
};

inline bool InsertNew(PacketID_t id, createfunc_t pParent)
{
	if (!GetPacketHash().contains(id))
	{
		GetPacketHash()[ id ] = pParent;

		return true;
	}

	return false;
}

inline void IPacket::Copy(IPacket* pPacket)
{
	memcpy(GetHeader(), pPacket->GetHeader(), pPacket->GetPacketSize());
}

inline std::shared_ptr<IPacket> IPacket::Create(PacketID_t packetID)
{
	auto itr = GetPacketHash().find( packetID );

	if (itr == GetPacketHash().end())
	{
		return NULL;
	}

	return itr->second();
}

#ifdef _SERVER
inline void IPacket::SetSession(SSLSession* pSession)
{
	m_pSession = pSession;
}

inline SSLSession* IPacket::GetSession()
{
	return m_pSession;
}
#endif // _SERVER

inline Header_t::Header_t(UInt32 header, PacketID_t packetID, UInt32 length) :
	m_uiHeader(header), 
	m_PacketID(packetID),
	m_uiLength(length),
	m_uiCRC32(NULL)
{
}

inline bool Header_t::IsValid()
{
	return m_uiHeader == PACKET_HEADER && m_uiLength < (MAX_PACKET_SIZE + 1);
}

inline void Header_t::CalculateCRC()
{
	m_uiCRC32 = crc32_fast(this, GetPacketLength());
}

inline bool Header_t::ValidateCRC()
{
	uint32_t previousCRC = m_uiCRC32;
	ResetCRC();
	CalculateCRC();
	return previousCRC == m_uiCRC32;
}

inline void Header_t::ResetCRC()
{
	m_uiCRC32 = 0;
}

inline UInt32 Header_t::GetPacketHeader()
{
	return m_uiHeader;
}
inline PacketID_t Header_t::GetPacketID()
{
	return m_PacketID;
}
inline UInt32 Header_t::GetPacketCRC()
{
	return m_uiCRC32;
}
inline UInt32 Header_t::GetPacketLength()
{
	return m_uiLength;
}

inline void	Header_t::SetPacketHeader(UInt32 header)
{
	m_uiHeader = header;
}

inline void	Header_t::SetPacketID(PacketID_t id)
{
	m_PacketID = id;
}

inline void	Header_t::SetPacketCRC(UInt32 crc)
{
	m_uiCRC32 = crc;
}

inline void	Header_t::SetPacketLength(UInt32 length)
{
	m_uiLength = length;
}


#define BEGIN_PACKET( _Packet_Name ) \
	class _Packet_Name : public IPacket \
	{ \
	public:	\
		struct Packet_t; \
		Packet_t* Get() \
		{ \
			return &m_Packet; \
		} \
		virtual Header_t* GetHeader() \
		{ \
			return (Header_t*)Get(); \
		} \
		virtual size_t GetPacketSize() \
		{ \
			return sizeof(m_Packet); \
		} \
		virtual void Set(void* pSet) \
		{ \
			m_Packet = std::move( *(Packet_t*)pSet ); \
		} \
		virtual void Process(); \
	public: \
		struct Packet_t : protected Header_t \
		{ \
		private: \
			static constexpr PacketID_t s_PacketID = UTIL_fnv1a( #_Packet_Name ); \
			static inline bool s_bInitPacket = InsertNew( s_PacketID, []() -> std::shared_ptr<IPacket> { return std::static_pointer_cast<IPacket>( std::make_shared<_Packet_Name>() ); } ); \
		public: \
			Packet_t() : \
				Header_t(PACKET_HEADER, s_PacketID, sizeof(Packet_t)) \
			{ \
			} \

#define BEGIN_PACKET_BASE( _Packet_Name, _Parent ) \
	class _Packet_Name : public _Parent \
	{ \
	public:	\

#define END_PACKET_BASE( _Packet_Name ) \
	_Packet_Name:: m_Packet::s_PacketID = UTIL_fnv1a( #_Packet_Name ); \
	_Packet_Name:: m_Packet::s_bInitPacket = InsertNew( s_PacketID, []() -> std::shared_ptr<IPacket> { return std::static_pointer_cast<IPacket>( std::make_shared<_Packet_Name>() ); } ); \
	_Packet_Name:: m_Packet::m_PacketID = m_Packet::s_PacketID; \
	static_assert(sizeof(_Packet_Name ::Packet_t) < (MAX_PACKET_SIZE + 1), "Packet size is greater than MAX_PACKET_SIZE"); \

#define EXT_PACKET( ) \
		} m_Packet; \

#define END_PACKET_EXT( _Packet_Name ) \
	}; \
	static_assert(sizeof(_Packet_Name ::Packet_t) < (MAX_PACKET_SIZE + 1), "Packet size is greater than MAX_PACKET_SIZE"); \

#define END_PACKET( _Packet_Name ) \
		} m_Packet; \
	}; \
	static_assert(sizeof(_Packet_Name ::Packet_t) < (MAX_PACKET_SIZE + 1), "Packet size is greater than MAX_PACKET_SIZE"); \

#define PROCESS_PACKET( _Packet_Name ) \
	void _Packet_Name ::Process() 

#define EMPTY_PACKET( _Packet_Name ) \
	BEGIN_PACKET( _Packet_Name ) \
	END_PACKET( _Packet_Name ) \

#endif // !PACKET_HPP
