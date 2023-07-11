#pragma once

#include <asio.hpp>
#include <cstdint>
#include <deque>
#include <mutex>

class DataTransport
{
public:
    DataTransport(const uint16_t port);
    ~DataTransport();

    void serve();

    bool sendBlocking(const uint8_t *const buffer, const uint32_t bufferLen);
    bool receiveBlocking(uint8_t *const buffer, const uint32_t bufferSizeMax, uint32_t *const bufferReceivedLen);

private:
    class Session
    {
    public:
        Session(asio::ip::tcp::socket &&s);
        Session(Session &&s);

        void start();

        bool getData(uint8_t *const buffer, const uint32_t bufferSizeMAx, uint32_t *const bufferReceivedLen);

    private:
        static constexpr uint32_t maxBufSize = 1024;
        std::array<uint8_t, maxBufSize> mBuf;
        asio::ip::tcp::socket mSocket;

        struct ReceivedData
        {
            uint8_t buffer[maxBufSize];
            uint32_t bufferLen;
        };

        std::mutex mReceivedDataMutex;
        std::deque<ReceivedData> mReceivedData;
    };

    void socketRead();

    bool mServerRunning;
    uint16_t mServerPort;

    std::thread mIoContextThread;

    asio::io_context mIoContext;
    asio::ip::tcp::acceptor mAcceptor;

    std::vector<asio::ip::tcp::socket> mSockets;

    std::mutex mSessionsMutex;
    std::vector<Session> mSessions;
};
