#include "DataTransport.hpp"

#include <asio/ts/buffer.hpp>
#include <chrono>
#include <memory>
#include <thread>
#include <utility>

DataTransport::DataTransport(const uint16_t port)
    : mServerRunning(true)
    , mServerPort{port}
    , mIoContext{}
    , mAcceptor{mIoContext, asio::ip::tcp::endpoint{asio::ip::tcp::v4(), port}}
    , mSessionsMutex{}
    , mSessions{}
{
}

DataTransport::~DataTransport()
{
    mIoContextThread.join();
}

void DataTransport::serve()
{
    printf("Serving on port: %d\n", mServerPort);

    acceptHandler();

    mIoContextThread = std::thread{[this] { mIoContext.run(); }};
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
    mAcceptor.async_accept([this](std::error_code ec, asio::ip::tcp::socket socket) {
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

                                    std::lock_guard<std::mutex> l{mReceivedDataMutex};
                                    mReceivedData.push_back(std::move(data));
                                }
                            } //
    );
}

bool Session::getData(uint8_t *const buffer, const uint32_t bufferSizeMax, uint32_t *const bufferReceivedLen)
{
    {
        std::lock_guard<std::mutex> l{mReceivedDataMutex};
        if (mReceivedData.size() > 0)
        {
            ReceivedData &dat = mReceivedData.front();

            // TODO: read all data available data...
            assert(dat.bufferLen < bufferSizeMax);

            memcpy(buffer, dat.buffer, dat.bufferLen);
            *bufferReceivedLen = dat.bufferLen;

            mReceivedData.pop_front();

            return true;
        }
    }

    return false;
}
