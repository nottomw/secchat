#include "Utils.hpp"

#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>

std::string utils::formatCharacters( //
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    std::stringstream ss;

    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        const char charToPrint = isprint(buffer[i]) ? buffer[i] : 'X';
        ss << charToPrint;
    }

    return ss.str();
}

std::string utils::formatCharactersHex( //
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        ss << std::setw(2) << static_cast<uint32_t>(buffer[i]);
        if (i < (bufferSize - 1))
        {
            ss << " ";
        }
    }

    return ss.str();
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

std::string utils::formatCharacters(const char *const buffer, const uint32_t bufferSize)
{
    return formatCharacters((uint8_t *)buffer, bufferSize);
}

std::string utils::formatCharactersHex(const char *const buffer, const uint32_t bufferSize)
{
    return formatCharactersHex((uint8_t *)buffer, bufferSize);
}
