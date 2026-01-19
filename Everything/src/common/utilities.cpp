#include <fstream>
#include <vector>
#include <filesystem>
#include "utilities.hpp"

bool UTIL_ReadFile(const char* path, ByteVector& buf)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
    {
        printf("!file\n");
        return false;
    }

    std::streamsize size = file.tellg();
    if (size <= 0)
    {
        printf("size <= 0\n");
        return false;
    }

    buf.resize(static_cast<size_t>(size));

    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(buf.data()), size))
    {
        printf("!file.read(reinterpret_cast<char*>(buf.data()), size)\n");
        return false;
    }

    return true;
}

bool UTIL_WriteFile(const char* path, const ByteVector& buf)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file)
    {
        printf("!file (unable to open file for writing)\n");
        return false;
    }

    if (!file.write(reinterpret_cast<const char*>(buf.data()), buf.size()))
    {
        printf("!file.write(reinterpret_cast<const char*>(buf.data()), buf.size())\n");
        return false;
    }

    return true;
}

bool UTIL_FileExists(const char* path)
{
    std::ifstream file(path);
    return file.good();
}

bool UTIL_FolderExists(const char* path)
{
    if (std::filesystem::exists(path) && std::filesystem::is_directory(path))
    {
        return true;
    }

    return false;
}
