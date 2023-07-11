#pragma once

#include <cstdint>

class DataTransport
{
public:
    bool sendBlocking(const char *const buffer, const uint32_t bufferLen);
    bool receiveBlocking(char *const buffer, const uint32_t bufferSizeMax, char *const bufferReceivedLen);

    // TODO: mqueue
};
