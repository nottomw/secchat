#pragma once

#include <asio.hpp>
#include <cstdint>
#include <deque>
#include <mutex>

class Session
{
public:
    using IdType = uint32_t;

    Session(asio::ip::tcp::socket &&s, const std::string &sessionName);
    Session(Session &&s);

    void start();

    asio::ip::tcp::socket &getSocket();

    void invalidate();
    bool isValid() const;

    IdType getId() const;

    bool operator==(const Session &s);

    std::string getName() const;

private:
    struct ReceivedData
    {
        ReceivedData(const size_t bufferLen);
        std::shared_ptr<uint8_t[]> mBuffer;
        size_t mBufferLen;
    };

    static constexpr uint32_t kMaxBufSize = 1024;
    uint8_t mRawBuffer[kMaxBufSize];

    asio::ip::tcp::socket mSocket;

    bool mValid;

    static IdType mGlobalSessionCounter;
    IdType mSessionId;

    std::mutex mReceivedDataQueueMutex;
    std::deque<ReceivedData> mReceivedDataQueue;

    const std::string mSessionName;

    bool getData( //
        uint8_t *const buffer,
        const uint32_t bufferSizeMax,
        uint32_t *const bufferReceivedLen);

    friend class DataTransport;
};
