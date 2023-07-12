#include "DataTransport.hpp"

#include <asio/ts/buffer.hpp>
#include <chrono>
#include <memory>
#include <thread>
#include <utility>

DataTransport::DataTransport()
    : mServerRunning(true)
    , mIoContext{}
    , mAcceptor{}
    , mSessionsMutex{}
    , mSessions{}
{
}

DataTransport::~DataTransport()
{
    mIoContext.stop();

    mIoContextThread.join();
}

void DataTransport::serve(const uint16_t port)
{
    printf("Serving on port: %d\n", port);

    mAcceptor = std::make_shared<asio::ip::tcp::acceptor>( //
        mIoContext,
        asio::ip::tcp::endpoint{asio::ip::tcp::v4(), port});

    acceptHandler();

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
            }
        }

        acceptHandler();
    });
}

Session::Session(asio::ip::tcp::socket &&s)
    : mRawBuffer{}
    , mSocket{std::move(s)}
{
}

Session::Session(Session &&s)
    : mSocket{std::move(s.mSocket)}
    , mReceivedData{std::move(s.mReceivedData)}
{
}

void Session::start()
{
    mSocket.async_read_some(asio::buffer(mRawBuffer, 1024), //
                            [this](std::error_code ec, std::size_t length) {
                                if (!ec)
                                {
                                    ReceivedData data;

                                    assert(length < 1024);

                                    memcpy(data.buffer, mRawBuffer, length);
                                    data.bufferLen = length;

                                    {
                                        std::lock_guard<std::mutex> l{mReceivedDataMutex};
                                        mReceivedData.push_back(std::move(data));
                                    }

                                    start();
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
        std::lock_guard<std::mutex> l{mReceivedDataMutex};
        if (mReceivedData.size() > 0)
        {
            ReceivedData &dat = mReceivedData.front();

            // TODO: read all available data up to max size of buffer...
            assert(dat.bufferLen < bufferSizeMax);

            memcpy(buffer, dat.buffer, dat.bufferLen);
            *bufferReceivedLen = dat.bufferLen;

            mReceivedData.pop_front();

            return true;
        }
    }

    return false;
}
