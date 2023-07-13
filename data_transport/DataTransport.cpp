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

    printf("Serving on port: %d\n", port);

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

    for (const auto &ep : endpoints)
    {
        printf("Connecting to endpoint: %s\n", ep.host_name().c_str());
    }

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
                                    uint32_t *const bufferReceivedLen)
{
    *bufferReceivedLen = 0U;

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
            printf("Socket accepted from: %s\n", remoteEp.address().to_string().c_str());

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

Session::Session(asio::ip::tcp::socket &&s)
    : mRawBuffer{}
    , mSocket{std::move(s)}
{
}

Session::Session(Session &&s)
    : mSocket{std::move(s.mSocket)}
    , mReceivedDataQueue{std::move(s.mReceivedDataQueue)}
{
}

void Session::start()
{
    mSocket.async_read_some(asio::buffer(mRawBuffer, 1024), //
                            [this](std::error_code ec, std::size_t length) {
                                if (!ec)
                                {
                                    ReceivedData data{length};
                                    memcpy(data.mBuffer.get(), mRawBuffer, length);

                                    {
                                        std::lock_guard<std::mutex> l{mReceivedDataQueueMutex};
                                        mReceivedDataQueue.push_back(std::move(data));
                                    }

                                    start(); // continue receiving
                                }
                            } //
    );
}

asio::ip::tcp::socket &Session::getSocket()
{
    return mSocket;
}

bool Session::getData(uint8_t *const buffer, const uint32_t bufferSizeMax, uint32_t *const bufferReceivedLen)
{
    {
        std::lock_guard<std::mutex> l{mReceivedDataQueueMutex};
        if (mReceivedDataQueue.size() > 0)
        {
            ReceivedData &dat = mReceivedDataQueue.front();

            assert(dat.mBufferLen < bufferSizeMax);

            memcpy(buffer, dat.mBuffer.get(), dat.mBufferLen);
            *bufferReceivedLen = dat.mBufferLen;

            mReceivedDataQueue.pop_front();

            return true;
        }
    }

    return false;
}

Session::ReceivedData::ReceivedData(const size_t bufferLen)
    : mBuffer{std::shared_ptr<uint8_t[]>(new uint8_t[bufferLen])}
    , mBufferLen{bufferLen}
{
}
