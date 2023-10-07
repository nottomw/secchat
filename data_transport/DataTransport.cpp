#include "DataTransport.hpp"

#include "Utils.hpp"

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
    , mSessions{}
    , mInvalidatedSessionCollectorShouldRun{true}
    , mInvalidatedSessionsCollectorThread{&DataTransport::invalidatedSessionsCollect, this}
{
}

DataTransport::~DataTransport()
{
    mIoContext.stop();

    if (mIoContextThread.joinable())
    {
        mIoContextThread.join();
    }

    mInvalidatedSessionCollectorShouldRun = false;
    if (mInvalidatedSessionsCollectorThread.joinable())
    {
        mInvalidatedSessionsCollectorThread.join();
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

void DataTransport::onDisconnect(const DataTransport::FnOnDisconnectHandler handler)
{
    mOnDisconnectHandler = handler;
}

void DataTransport::connect(const std::string &ipAddr, const uint16_t port)
{
    setTransportMode(Mode::kClient);

    // TODO: there should be a possibility to verify the connection was successful

    mResolver = std::make_shared<asio::ip::tcp::resolver>(mIoContext);

    auto endpoints = mResolver->resolve(ipAddr, std::to_string(port));

    asio::ip::tcp::socket sock(mIoContext);
    asio::connect(sock, endpoints);

    auto session = std::make_shared<Session>(std::move(sock));
    session->start();

    mSessions.access(                 //
        [&](SessionsVector &sessions) //
        {                             //
            sessions.push_back(std::move(session));
        });

    mIoContextThread = std::thread{[this] { mIoContext.run(); }};
}

bool DataTransport::sendBlocking(const uint8_t *const buffer, const uint32_t bufferLen)
{
    // sending to all session sockets here

    // pretty big lock...

    mSessions.access(                 //
        [&](SessionsVector &sessions) //
        {                             //
            for (auto &it : sessions)
            {
                asio::error_code err;

                auto &sock = it->getSocket();
                auto buf = asio::buffer(buffer, bufferLen);
                size_t wrote = 0;

                try
                {
                    wrote = asio::write(sock, buf, err);
                }
                catch (...)
                {
                    // got some error, probably peer disconnected already...
                    it->invalidate();
                    continue;
                }

                if (err == asio::error::eof)
                {
                    it->invalidate();
                    continue;
                }
                else if (err)
                {
                    utils::log("[transport] WRITE ERROR: %s, %d to session: #%d", //
                               err.message().c_str(),
                               err.value(),
                               it->getId());
                    it->invalidate();
                    continue;
                }
                else
                {
                    // probably sesion disconnected, will be removed later
                    if (wrote != bufferLen)
                    {
                        utils::log(
                            "[transport] could not send whole message to session #%d (%d/%d)", //
                            it->getId(),
                            wrote,
                            bufferLen);
                        continue;
                    }
                }
            }
        });

    return true;
}

bool DataTransport::sendBlocking( //
    const uint8_t *const buffer,
    const uint32_t bufferLen,
    std::shared_ptr<Session> session)
{
    if (!session)
    {
        return false;
    }

    asio::error_code err;

    auto &sock = session->getSocket();
    auto buf = asio::buffer(buffer, bufferLen);
    size_t wrote = 0;

    try
    {
        wrote = asio::write(sock, buf, err);
    }
    catch (...)
    {
        // got some error, probably peer disconnected already...
        session->invalidate();
        return false;
    }

    if (err == asio::error::eof)
    {
        session->invalidate();
        return false;
    }
    else if (err)
    {
        utils::log("[transport] WRITE ERROR: %s, %d to session: #%d", //
                   err.message().c_str(),
                   err.value(),
                   session->getId());
        session->invalidate();
        return false;
    }
    else if (wrote != bufferLen)
    {
        utils::log("[transport] could not send whole message to session #%d (%d/%d)", //
                   session->getId(),
                   wrote,
                   bufferLen);
        return false;
    }

    return true;
}

std::weak_ptr<Session> DataTransport::receiveBlocking(uint8_t *const buffer,
                                                      const uint32_t bufferSizeMax,
                                                      uint32_t *const bufferReceivedLen,
                                                      const uint64_t timeoutMs)
{
    *bufferReceivedLen = 0U;

    constexpr uint64_t kLoopWaitTimeMs = 100U;
    uint64_t totalWaitTime = 0U;

    std::weak_ptr<Session> retVal{};

    while (true)
    {
        const bool timeoutArmed = (timeoutMs != 0U);
        const bool timeoutHappened = (totalWaitTime > timeoutMs);
        if (timeoutArmed && timeoutHappened)
        {
            return std::weak_ptr<Session>{};
        }

        mSessions.access(                 //
            [&](SessionsVector &sessions) //
            {                             //
                for (auto &it : sessions)
                {
                    const bool recvOk = it->getData(buffer, bufferSizeMax, bufferReceivedLen);
                    if (recvOk)
                    {
                        retVal = it;
                        break;
                    }
                }
            });

        if (retVal.lock())
        {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(kLoopWaitTimeMs));
        totalWaitTime += kLoopWaitTimeMs;
    }

    return retVal;
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
            utils::log("[server] accepted connection from: %s",
                       remoteEp.address().to_string().c_str());

            {
                auto session = std::make_shared<Session>( //
                    std::move(socket));
                session->start();

                mSessions.access(                 //
                    [&](SessionsVector &sessions) //
                    {                             //
                        sessions.push_back(std::move(session));
                    });

                if (mOnConnectHandler)
                {
                    mOnConnectHandler();
                }
            }
        }

        acceptHandler(); // continue accepting
    });
}

void DataTransport::invalidatedSessionsCollect()
{
    utils::log("[session collector] started");

    // From time to time remove all sessions that were invalidated
    while (mInvalidatedSessionCollectorShouldRun)
    {
        uint32_t removedSessions = 0U;

        auto removeCondition =                      //
            [&](std::shared_ptr<Session> session) { //
                const bool sessionValid = session->isValid();

                if (!sessionValid)
                {
                    // there is a chance that the session internals (socket)
                    // are now destroyed, cannot display anything more than
                    // info on removing session

                    utils::log("[session collector] removing session id #%d", session->getId());

                    removedSessions += 1U;

                    // Calling disconnect handler here can be pretty late, maybe
                    // should be called during invalidate() on session?
                    if (mOnDisconnectHandler)
                    {
                        mOnDisconnectHandler(session);
                    }

                    return true; // should be removed
                }

                return false;
            };

        mSessions.access(                 //
            [&](SessionsVector &sessions) //
            {                             //
                sessions.erase(           //
                    std::remove_if(       //
                        sessions.begin(),
                        sessions.end(),
                        removeCondition),
                    sessions.end());
            });

        if (removedSessions > 0)
        {
            utils::log("[session collector] removed %d invalidated sessions", removedSessions);
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}
