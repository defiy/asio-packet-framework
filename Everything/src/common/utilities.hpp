#ifndef UTILITIES_HPP
#define UTILITIES_HPP

#include <cstdint>
#include <system_error>
#include <cstdarg>
#include <vector>
#include <platform.hpp>

typedef std::vector<Byte> ByteVector;

constexpr std::size_t FNV1a_prime = 0x01000193; // 16777619
constexpr std::size_t FNV1a_offset_basis = 0x811C9DC5; // 2166136261

constexpr std::size_t UTIL_fnv1a(const char* str, std::size_t hash = FNV1a_offset_basis) {
	return (*str == '\0') ? hash : UTIL_fnv1a(str + 1, (hash ^ static_cast<unsigned char>(*str)) * FNV1a_prime);
}
template <std::size_t N> constexpr std::size_t UTIL_fnv1a(const char(&str)[N]) {
	return UTIL_fnv1a(str);
}

bool UTIL_ReadFile(const char* path, ByteVector& buf);
bool UTIL_WriteFile(const char* path, const ByteVector& buf);
bool UTIL_FileExists(const char* path);
bool UTIL_FolderExists(const char* path);


class CCustomErrorCategory : public std::error_category
{
public:
	inline CCustomErrorCategory(std::string szName, const char* szMessage, ...) :
		m_szName( szName ) 
	{
		// Initialize va_list to store the additional arguments
		va_list args;
		va_start(args, szMessage);

		char buf[255];

		vsprintf( buf, szMessage, args );
		m_szMessage = buf;

		// Clean up the va_list
		va_end(args);
	}

	const char* name() const noexcept override {
		return m_szName.c_str();
	}
	std::string message(int ev) const override {
		return m_szMessage;
	}
private:
	std::string m_szName;
	std::string m_szMessage;
};

template<size_t N>
class ConstBuffer
{
public:
	template <size_t M>
	void Set(Byte(&bytes)[M]);
	void Set(Byte* bytes, int size);

	size_t Size();

	template <size_t M>
	void operator=(Byte(&bytes)[M]);
	Byte& operator[](int n);

private:
	Byte m_Buf[ N ];
};

template<size_t N> template<size_t M>
inline void ConstBuffer<N>::Set(Byte(&bytes)[M])
{
	static_assert(N == M, "Invalid ConstBuffer Set!!");

	memcpy( m_Buf, bytes, N );
}

template<size_t N> template<size_t M>
inline void ConstBuffer<N>::operator=(Byte(&bytes)[M])
{
	ConstBuffer<N>::Set<M>( bytes );
}

template<size_t N>
inline void ConstBuffer<N>::Set(Byte* bytes, int size)
{
	memcpy( m_Buf, bytes, size );
}

template<size_t N>
inline size_t ConstBuffer<N>::Size()
{
	return N;
}

template<size_t N>
inline Byte& ConstBuffer<N>::operator[](int n)
{
	return m_Buf[ N ];
}

#endif
