#include "SecchatServer.hpp"

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
                {
                    // DBG
                    printf("[server] RX: ");
                    for (size_t i = 0; i < recvdLen; ++i)
                    {
                        printf("%c", rawBuf[i]);
                    }
                    printf("\n");
                    fflush(stdout);
                }

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
    // echo to all for now
    mTransport.sendBlocking(data, dataLen);
}
