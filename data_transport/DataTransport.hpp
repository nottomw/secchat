#pragma once

#include "Session.hpp"

#include <asio.hpp>
#include <cstdint>
#include <mutex>

class DataTransport
{
public:
    DataTransport();
    ~DataTransport();

    using FnOnConnectHandler = std::function<void(void)>;

    void serve(const uint16_t port);
    void onServerConnect(const FnOnConnectHandler handler);

    void connect(const std::string &ipAddr, const uint16_t port);

    bool sendBlocking(const uint8_t *const buffer, const uint32_t bufferLen);
    bool sendBlocking(const uint8_t *const buffer, const uint32_t bufferLen, std::shared_ptr<Session> session);

    std::weak_ptr<Session> receiveBlocking(uint8_t *const buffer, //
                                           const uint32_t bufferSizeMax,
                                           uint32_t *const bufferReceivedLen,
                                           const uint64_t timeoutMs = 2000U);

private:
    enum class Mode
    {
        kNone,
        kServer,
        kClient,
    };

    Mode mCurrentMode;
    bool mServerRunning;

    std::thread mIoContextThread;

    asio::io_context mIoContext;

    std::shared_ptr<asio::ip::tcp::acceptor> mAcceptor;
    std::shared_ptr<asio::ip::tcp::resolver> mResolver;

    std::vector<asio::ip::tcp::socket> mSockets;

    std::mutex mSessionsMutex;
    std::vector<std::shared_ptr<Session>> mSessions;

    FnOnConnectHandler mOnConnectHandler;

    bool mInvalidatedSessionCollectorShouldRun;
    std::thread mInvalidatedSessionsCollectorThread;

    void setTransportMode(const Mode newMode);
    void acceptHandler();
    void invalidatedSessionsCollect();
};
