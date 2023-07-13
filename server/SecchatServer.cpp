#include "SecchatServer.hpp"

#include "Proto.hpp"
#include "Utils.hpp"

SecchatServer::SecchatServer()
    : mReaderShouldRun{true}
    , mClientsCount{0U}
{
    if (!mCrypto.init())
    {
        printf("Crypto init failed\n");
    }
}

void SecchatServer::start(const uint16_t serverPort)
{
    mTransport.serve(serverPort);

    // TODO: maybe on server connect should provide a way to talk only
    // to the new client (socket? overloaded sendBlocking()?)
    mTransport.onServerConnect( //
        [&] {
            mClientsCount += 1U;
            printf("[server] new connection, clients: %d...\n", mClientsCount);

            fflush(stdout);
        });

    mChatReader = std::thread{[&]() {
        while (mReaderShouldRun)
        {
            uint8_t rawBuf[1024];
            uint32_t recvdLen = 0;
            const bool dataOk = mTransport.receiveBlocking(rawBuf, 1024, &recvdLen);
            if (dataOk)
            {
                handlePacket(rawBuf, recvdLen);
            }
        }
    }};
}

void SecchatServer::stop()
{
    mReaderShouldRun = false;
    mChatReader.join();
}

void SecchatServer::handlePacket(const uint8_t *const data, const uint32_t dataLen)
{
    auto receivedFrames = Proto::deserialize(data, dataLen);

    for (auto &framesIt : receivedFrames)
    {
        Proto::Payload &payload = framesIt.getPayload();
        switch (payload.type)
        {
            case Proto::PayloadType::kNewUser:
                printf("[server] new user created: ");
                utils::printCharacters(payload.payload.get(), payload.payloadSize);
                fflush(stdout);
                // TODO: handle properly
                break;

            case Proto::PayloadType::kJoinChatRoom:
                printf("[server] chatroom join requested created ");
                utils::printCharacters(payload.payload.get(), payload.payloadSize);
                fflush(stdout);
                // TODO: handle properly
                break;

            default:
                // echo all others to all users
                printf("NOT FORWARDING: ");
                utils::printCharacters(data, dataLen);
                fflush(stdout);
                //                mTransport.sendBlocking(data, dataLen);
                break;
        }
    }

    fflush(stdout);

    // handle sym key exchange -> forward user pub key to all users
    // handle asym key exchange -> forward to all users
    // handle messages -> forward
}
