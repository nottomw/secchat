#pragma once

#include "ByteArray.hpp"

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

namespace utils
{

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
    // maybe could log to a file too
}

// For now placed here due to lack of better place, should
// be moved somewhere else probably...
std::string formatChatMessage( //
    const std::string &roomName,
    const std::string &userName,
    const std::string &message = "");

} // namespace utils
