#pragma once

#include <asio.hpp>
#include <cstdint>
#include <deque>
#include <mutex>

class Session : public std::enable_shared_from_this<Session>
{
public:
    Session(asio::ip::tcp::socket &&s);
    Session(Session &&s);

    void start();

    bool getData(uint8_t *const buffer, const uint32_t bufferSizeMAx, uint32_t *const bufferReceivedLen);

private:
    static constexpr uint32_t maxBufSize = 1024;
    uint8_t mRawBuffer[1024];

    asio::ip::tcp::socket mSocket;

    struct ReceivedData
    {
        uint8_t buffer[maxBufSize];
        uint32_t bufferLen;
    };

    std::mutex mReceivedDataMutex;
    std::deque<ReceivedData> mReceivedData;
};

class DataTransport
{
public:
    DataTransport(const uint16_t port);
    ~DataTransport();

    void serve();

    bool sendBlocking(const uint8_t *const buffer, const uint32_t bufferLen);
    bool receiveBlocking(uint8_t *const buffer, const uint32_t bufferSizeMax, uint32_t *const bufferReceivedLen);

private:
    bool mServerRunning;
    uint16_t mServerPort;

    std::thread mIoContextThread;

    asio::io_context mIoContext;
    asio::ip::tcp::acceptor mAcceptor;

    std::vector<asio::ip::tcp::socket> mSockets;

    std::mutex mSessionsMutex;
    std::vector<std::shared_ptr<Session>> mSessions;

    void acceptHandler();
};
