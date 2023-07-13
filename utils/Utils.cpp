#include "Utils.hpp"

#include <cstdio>

void utils::printCharacters(const uint8_t *const buffer, const uint32_t bufferSize, const char lastChar)
{
    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        printf("%c", buffer[i]);
    }

    printf("%c", lastChar);
}
