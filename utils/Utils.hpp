#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

namespace utils
{

// TODO: use the bytearray everywhere when possible instead of uint8+size...
// Poor man's byte array for now
class ByteArray
{
public:
    ByteArray() = default;
    ByteArray(const uint32_t size);
    ByteArray(const uint8_t *const newData, const uint32_t newSize);

    // add cast operators so it's a little easier to use
    // while passing as argument
    operator size_t() const
    {
        return dataSize;
    }

    operator void *() const
    {
        return data.get();
    }

    uint8_t *ptr() const
    {
        return data.get();
    }

    uint32_t size() const
    {
        return dataSize;
    }

    std::unique_ptr<uint8_t[]> data;
    uint32_t dataSize;
};

std::string formatCharacters( //
    const uint8_t *const buffer,
    const uint32_t bufferSize);

std::string formatCharacters( //
    const char *const buffer,
    const uint32_t bufferSize);

std::string formatCharactersHex( //
    const uint8_t *const buffer,
    const uint32_t bufferSize);

std::string formatCharactersHex( //
    const char *const buffer,
    const uint32_t bufferSize);

template <typename... Ts>
void log(const char *const fmt, Ts... params)
{
#if (!LOGGING_QUIET)
    printf(fmt, params...);
    printf("\n"); // hack to add new line
    fflush(stdout);
#endif
    // TODO: log to file
}

// For now placed here due to lack of better place, should
// be moved somewhere else probably...
std::string formatChatMessage( //
    const std::string &roomName,
    const std::string &userName,
    const std::string &message = "");

} // namespace utils
