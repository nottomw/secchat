#include "Utils.hpp"

#include <cstdio>

void utils::printCharacters( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar)
{
    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        utils::log("%c", buffer[i]);
    }

    utils::log("%c", lastChar);

    fflush(stdout);
}

void utils::printCharactersHex( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar)
{
    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        utils::log("%02x ", buffer[i]);
    }

    utils::log("%c", lastChar);

    fflush(stdout);
}

std::string utils::formatChatMessage( //
    const std::string &roomName,
    const std::string &userName,
    const std::string &message)
{
    std::string retStr;
    retStr += "[";
    retStr += roomName;
    retStr += "]";
    retStr += "<";
    retStr += userName;
    retStr += "> ";
    retStr += message;

    return retStr;
}
