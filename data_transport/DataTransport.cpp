#include "DataTransport.hpp"

#include <chrono>
#include <thread>

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

    mAcceptor.async_accept([this](std::error_code ec, asio::ip::tcp::socket socket) {
        if (!ec)
        {
            auto remoteEp = socket.remote_endpoint();
            printf("Socket accepted from: %s\n", remoteEp.address().to_string().c_str());

            {
                Session session(std::move(socket));
                session.start();

                {
                    std::lock_guard<std::mutex> l{mSessionsMutex};
                    mSessions.push_back(std::move(session));
                }
            }
        }

        serve();
    });

    mIoContextThread = std::thread{[this] { mIoContext.run(); }};
}

bool DataTransport::receiveBlocking(uint8_t *const buffer,
                                    const uint32_t bufferSizeMax,
                                    uint32_t *const bufferReceivedLen)
{
    (void)buffer;
    (void)bufferReceivedLen;
    (void)bufferSizeMax;

    *bufferReceivedLen = 0U;

    {
        std::lock_guard<std::mutex> l{mSessionsMutex};
        for (auto &it : mSessions)
        {
            const bool recvOk = it.getData(buffer, bufferSizeMax, bufferReceivedLen);
            if (recvOk)
            {
                return true;
            }
        }
    }

    return false;
}

DataTransport::Session::Session(asio::ip::tcp::socket &&s)
    : mBuf{}
    , mSocket{std::move(s)}
{
}

DataTransport::Session::Session(DataTransport::Session &&s)
    : mSocket{std::move(s.mSocket)}
    , mReceivedData{std::move(s.mReceivedData)}
{
}

void DataTransport::Session::start()
{
    asio::mutable_buffer asioBuf{mBuf.data(), mBuf.size()};
    mSocket.async_read_some(asioBuf, //
                            [this](std::error_code ec, std::size_t length) {
                                if (!ec)
                                {
                                    ReceivedData data;
                                    memcpy(data.buffer, mBuf.data(), length);
                                    data.bufferLen = length;

                                    mReceivedData.push_back(std::move(data));
                                }
                            } //
    );
}

bool DataTransport::Session::getData(uint8_t *const buffer,
                                     const uint32_t bufferSizeMax,
                                     uint32_t *const bufferReceivedLen)
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
