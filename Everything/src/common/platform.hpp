#ifndef PLATFORM_HPP
#define PLATFORM_HPP

#if defined(__x86_64__) || defined(_WIN64)
#define PLATFORM_64BITS 1
#endif

#ifdef _WIN32

typedef unsigned __int8			Byte;

typedef __int16					Short;
typedef unsigned __int16		UShort;

#ifdef PLATFORM_64BITS
typedef unsigned __int64		UIntPtr;
typedef __int64					IntPtr;
#else
typedef unsigned __int32		UIntPtr;
typedef __int32					IntPtr;
#endif // PLATFORM_64BITS

typedef __int16					Int8;
typedef unsigned __int16		UInt8;
typedef __int16					Int16;
typedef unsigned __int16		UInt16;
typedef __int32					Int32;
typedef unsigned __int32		UInt32;
typedef __int64					Int64;
typedef unsigned __int64		UInt64;

#else

typedef unsigned char			Byte;

typedef short					Short;
typedef unsigned short			UShort;

#ifdef PLATFORM_64BITS
typedef unsigned long long		UIntPtr;
typedef long long				IntPtr;
#else
typedef unsigned int			UIntPtr;
typedef int						IntPtr;
#endif // PLATFORM_64BITS

typedef char					Int8;
typedef unsigned char			UInt8;
typedef short					Int16;
typedef unsigned short			UInt16;
typedef int						Int32;
typedef unsigned int			UInt32;
typedef long long				Int64;
typedef unsigned long long		UInt64;

#endif // _WIN32

#endif // !PLATFORM_HPP
