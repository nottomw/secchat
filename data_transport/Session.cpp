#include "Session.hpp"

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
