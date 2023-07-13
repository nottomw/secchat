#pragma once

#include <cstdint>

class Proto
{
public:
    enum class FrameType
    {
        kUserAsymKeyExchange,
        kGroupSymKeyExchange,
        kMessageToServer, // server settings
        kMessageToRoom,
        kMessageToUser
    };

    struct Frame
    {
        uint64_t timestamp;
        FrameType type;

        char *source;
        uint32_t sourceLen;

        char *destination;
        uint32_t destinationSize;
        // checksum?
    };

    bool serialize(const Frame &frame) const;
    Frame deserialize(const char *const buffer, const uint32_t bufferLen) const;
};
