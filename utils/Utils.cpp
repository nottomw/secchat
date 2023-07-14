#include "Utils.hpp"

#include <cstdio>

void utils::printCharacters(const uint8_t *const buffer, const uint32_t bufferSize, const char lastChar)
{
    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        utils::log("%c", buffer[i]);
    }

    utils::log("%c", lastChar);

    fflush(stdout);
}

void utils::printCharactersHex(const uint8_t *const buffer, const uint32_t bufferSize, const char lastChar)
{
    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        utils::log("%02x ", buffer[i]);
    }

    utils::log("%c", lastChar);

    fflush(stdout);
}
