#include "Crypto.hpp"
#include "DataTransport.hpp"

#include <cstdio>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    Crypto crypto;
    if (!crypto.init())
    {
        printf("Crypto init failed\n");
    }

    printf("Hello world from server...\n");

    DataTransport tr;
    tr.serve(12345);

    uint8_t prompt[] = {'-', '-', '>', ' '};

    tr.onServerConnect([&] { tr.sendBlocking(prompt, sizeof(prompt)); });

    bool readerShouldRun = true;
    std::thread chatReader{[&]() {
        while (readerShouldRun)
        {
            uint8_t rawBuf[1024];
            uint32_t recvdLen = 0;
            const bool dataOk = tr.receiveBlocking(rawBuf, 1024, &recvdLen);

            if (dataOk)
            {
                printf("[server] received packet: ");
                for (size_t i = 0; i < recvdLen; ++i)
                {
                    printf("%c", rawBuf[i]);
                }
                printf("\n");
                fflush(stdout);

                tr.sendBlocking(prompt, sizeof(prompt));
            }
        }
    }};

    while (true)
    {
        // nothing...
    }

    readerShouldRun = false;
    chatReader.join();

    return 0;
}
