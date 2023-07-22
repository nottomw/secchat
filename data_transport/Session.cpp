#include "Session.hpp"

#include "Utils.hpp"

Session::IdType Session::mGlobalSessionCounter = 0U;

Session::Session( //
    asio::ip::tcp::socket &&s,
    const std::string &sessionName)
    : mRawBuffer{}
    , mSocket{std::move(s)}
    , mValid{true}
    , mSessionId{mGlobalSessionCounter++}
    , mReceivedDataQueue{}
    , mSessionName{sessionName}
{
}

Session::Session(Session &&s)
    : mRawBuffer{}
    , mSocket{std::move(s.mSocket)}
    , mValid{true}
    , mSessionId{mGlobalSessionCounter++}
    , mReceivedDataQueue{std::move(s.mReceivedDataQueue)}
    , mSessionName{std::move(s.mSessionName)}
{
}

void Session::start()
{
    mSocket.async_read_some(
        asio::buffer(mRawBuffer, 1024), //
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
            else if ((ec == asio::error::eof) || //
                     (ec == asio::error::connection_reset))
            {
                invalidate();
            }
            else
            {
                utils::log("[session] READ ERROR: %s, %d", ec.message().c_str(), ec.value());
            }
        } //
    );
}

asio::ip::tcp::socket &Session::getSocket()
{
    return mSocket;
}

void Session::invalidate()
{
    utils::log("[session] INVALIDATED: %s", getName());
    mValid = false; // scheduled for disposal
}

bool Session::isValid() const
{
    return mValid;
}

Session::IdType Session::getId() const
{
    return mSessionId;
}

bool Session::operator==(const Session &s)
{
    return (getId() == s.getId());
}

std::string Session::getName() const
{
    return mSessionName;
}

bool Session::getData(uint8_t *const buffer,
                      const uint32_t bufferSizeMax,
                      uint32_t *const bufferReceivedLen)
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
