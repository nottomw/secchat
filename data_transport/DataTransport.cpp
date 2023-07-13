#include "DataTransport.hpp"

#include <asio/ts/buffer.hpp>
#include <chrono>
#include <memory>
#include <thread>
#include <utility>

DataTransport::DataTransport()
    : mCurrentMode{Mode::kNone}
    , mServerRunning{true}
    , mIoContext{}
    , mAcceptor{}
    , mResolver{}
    , mSessionsMutex{}
    , mSessions{}
{
}

DataTransport::~DataTransport()
{
    mIoContext.stop();

    if (mIoContextThread.joinable())
    {
        mIoContextThread.join();
    }
}

void DataTransport::serve(const uint16_t port)
{
    setTransportMode(Mode::kServer);

    mAcceptor = std::make_shared<asio::ip::tcp::acceptor>( //
        mIoContext,
        asio::ip::tcp::endpoint{asio::ip::tcp::v4(), port});

    acceptHandler();

    mIoContextThread = std::thread{[this] { mIoContext.run(); }};
}

void DataTransport::onServerConnect(const DataTransport::FnOnConnectHandler handler)
{
    mOnConnectHandler = handler;
}

void DataTransport::connect(const std::string &ipAddr, const uint16_t port)
{
    setTransportMode(Mode::kClient);

    mResolver = std::make_shared<asio::ip::tcp::resolver>(mIoContext);

    auto endpoints = mResolver->resolve(ipAddr, std::to_string(port));

    asio::ip::tcp::socket sock(mIoContext);
    asio::connect(sock, endpoints);

    auto session = std::make_shared<Session>(std::move(sock));
    session->start();

    {
        std::lock_guard<std::mutex> l{mSessionsMutex};
        mSessions.push_back(std::move(session));
    }

    mIoContextThread = std::thread{[this] { mIoContext.run(); }};
}

bool DataTransport::sendBlocking(const uint8_t *const buffer, const uint32_t bufferLen)
{
    // sending to all session sockets here, naive approach

    for (auto &it : mSessions)
    {
        auto &sock = it->getSocket();

        auto buf = asio::buffer(buffer, bufferLen);
        size_t wrote = asio::write(sock, buf);
        assert(wrote == bufferLen);
    }

    return true;
}

bool DataTransport::receiveBlocking(uint8_t *const buffer,
                                    const uint32_t bufferSizeMax,
                                    uint32_t *const bufferReceivedLen,
                                    const uint64_t timeoutMs)
{
    *bufferReceivedLen = 0U;

    constexpr uint64_t kLoopWaitTimeMs = 300U;
    uint64_t totalWaitTime = 0U;

    while (true)
    {
        const bool timeoutArmed = (timeoutMs != 0U);
        const bool timeoutHappened = (totalWaitTime > timeoutMs);
        if (timeoutArmed && timeoutHappened)
        {
            return false;
        }

        {
            std::lock_guard<std::mutex> l{mSessionsMutex};
            for (auto &it : mSessions)
            {
                const bool recvOk = it->getData(buffer, bufferSizeMax, bufferReceivedLen);
                if (recvOk)
                {
                    return true;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(kLoopWaitTimeMs));
        totalWaitTime += kLoopWaitTimeMs;
    }

    return false;
}

void DataTransport::setTransportMode(const DataTransport::Mode newMode)
{
    switch (mCurrentMode)
    {
        case Mode::kNone:
            mCurrentMode = newMode;
            break;

        case Mode::kClient:
            assert(newMode == Mode::kClient);
            break;

        case Mode::kServer:
            assert(newMode == Mode::kServer);
            break;

        default:
            assert(NULL != "incorrect DataTransport mode set");
            break;
    }
}

void DataTransport::acceptHandler()
{
    mAcceptor->async_accept([this](std::error_code ec, asio::ip::tcp::socket socket) {
        if (!ec)
        {
            auto remoteEp = socket.remote_endpoint();
            printf("Accepted connection from: %s\n", remoteEp.address().to_string().c_str());

            {
                auto session = std::make_shared<Session>(std::move(socket));
                session->start();

                {
                    std::lock_guard<std::mutex> l{mSessionsMutex};
                    mSessions.push_back(std::move(session));
                }

                mOnConnectHandler();
            }
        }

        acceptHandler(); // continue accepting
    });
}
