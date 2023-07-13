#pragma once

#include <asio.hpp>
#include <cstdint>
#include <deque>
#include <mutex>

class Session
{
public:
    Session(asio::ip::tcp::socket &&s);
    Session(Session &&s);

    void start();

    asio::ip::tcp::socket &getSocket();
    bool getData(uint8_t *const buffer, const uint32_t bufferSizeMAx, uint32_t *const bufferReceivedLen);

private:
    static constexpr uint32_t kMaxBufSize = 1024;
    uint8_t mRawBuffer[kMaxBufSize];

    asio::ip::tcp::socket mSocket;

    struct ReceivedData
    {
        ReceivedData(const size_t bufferLen);
        std::shared_ptr<uint8_t[]> mBuffer;
        size_t mBufferLen;
    };

    std::mutex mReceivedDataQueueMutex;
    std::deque<ReceivedData> mReceivedDataQueue;
};
