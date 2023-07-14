#pragma once

#include <cstdint>

namespace utils
{

void printCharacters(const uint8_t *const buffer, const uint32_t bufferSize, const char lastChar = '\n');

void printCharactersHex(const uint8_t *const buffer, const uint32_t bufferSize, const char lastChar = '\n');

} // namespace utils
