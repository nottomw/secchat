#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace utils
{

void printCharacters( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar = '\n');
void printCharactersHex( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar = '\n');

// TODO: define for log so format string is literal

template <typename... Ts>
void log(const char *const fmt, Ts... params)
{
#if (!LOGGING_QUIET)
    printf(fmt, params...);
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
