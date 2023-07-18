#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

namespace utils
{

// Poor man's byte array for now
class ByteArray
{
public:
    ByteArray() = default;
    ByteArray(const uint32_t size);

    std::unique_ptr<uint8_t[]> data;
    uint32_t dataSize;
};

void printCharacters( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar = '\n');

void printCharactersHex( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar = '\n');

template <typename... Ts>
void log(const char *const fmt, Ts... params)
{
#if (!LOGGING_QUIET)
    printf(fmt, params...);
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
