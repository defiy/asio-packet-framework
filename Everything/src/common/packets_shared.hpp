#ifndef PACKETS_SH_HPP
#define PACKETS_SH_HPP

#include "packet.hpp"

struct _StreamPacket_t : protected Header_t
{
	bool m_bClear = false;
	bool m_bTrailing = false;
	UInt16 m_Length = 0;
	Byte m_StreamBuf[MAX_PACKET_LENGTH - 4 - (sizeof(UIntPtr) - 4)];
};

// -2 to use remaining packet, other to align it
#define STREAM_PACKET( _Name ) \
	BEGIN_PACKET(_Name) \
		bool m_bClear = false; \
		bool m_bTrailing = false; \
		UInt16 m_Length = 0; \
		Byte m_StreamBuf[MAX_PACKET_LENGTH - 4 - (sizeof(UIntPtr) - 4)]; \
	EXT_PACKET() \
		static inline std::vector<Byte> m_vecCopy; \
		void ProcessStream(bool trl, std::vector<Byte>& vec); \
	END_PACKET_EXT(_Name) \
	inline PROCESS_PACKET( _Name ) \
	{ \
		if (Get()->m_bClear) \
		{ \
			m_vecCopy.clear(); \
		} \
		m_vecCopy.insert(m_vecCopy.end(), Get()->m_StreamBuf, Get()->m_StreamBuf + Get()->m_Length); \
		ProcessStream(Get()->m_bTrailing, m_vecCopy); \
	} \

#define PROCESS_STREAM( _Name, trl, vecVar ) \
	void _Name::ProcessStream( bool trl, std::vector<Byte>& vecVar )

BEGIN_PACKET(TestPacket)
	char m_Buf[255];
END_PACKET(TestPacket)

BEGIN_PACKET(MaxPacket)
	Byte m_MaxBuf[MAX_PACKET_LENGTH];
END_PACKET(MaxPacket)

/*
* Stream a ChainFile
*/
STREAM_PACKET( ChainFileStream );

/*
* Request a ChainFile from server
*/
EMPTY_PACKET(ChainFileRequest)

BEGIN_PACKET(ChatPacket)
	char m_Username[25];
	char m_Line[MAX_PACKET_LENGTH - 25];
END_PACKET(ChatPacket)

#endif