#include "SecchatServer.hpp"

SecchatServer::SecchatServer()
    : mReaderShouldRun{true}
{
    if (!mCrypto.init())
    {
        printf("Crypto init failed\n");
    }
}

void SecchatServer::start(const uint16_t serverPort)
{
    mTransport.serve(serverPort);

    uint8_t prompt[] = {'-', '-', '>', ' '};

    mTransport.onServerConnect( //
        [&] { mTransport.sendBlocking(prompt, sizeof(prompt)); });

    mChatReader = std::thread{[&]() {
        while (mReaderShouldRun)
        {
            uint8_t rawBuf[1024];
            uint32_t recvdLen = 0;
            const bool dataOk = mTransport.receiveBlocking(rawBuf, 1024, &recvdLen);
            if (dataOk)
            {
                printf("[server] received packet: ");
                for (size_t i = 0; i < recvdLen; ++i)
                {
                    printf("%c", rawBuf[i]);
                }
                printf("\n");
                fflush(stdout);

                mTransport.sendBlocking(prompt, sizeof(prompt));
            }
        }
    }};
}

void SecchatServer::stop()
{
    mReaderShouldRun = false;
    mChatReader.join();
}
