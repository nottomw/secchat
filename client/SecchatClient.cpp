#include "Crypto.hpp"
#include "DataTransport.hpp"

#include <chrono>
#include <cstdio>
#include <iostream>
#include <thread>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    Crypto crypto;
    if (!crypto.init())
    {
        printf("Crypto init failed\n");
    }

    printf("Hello world from client...\n");

    DataTransport tr;
    tr.connect("127.0.0.1", 12345);

    bool readerShouldRun = true;
    std::thread chatReader{[&readerShouldRun, &tr]() {
        while (readerShouldRun)
        {
            uint8_t rawBuf[1024];
            uint32_t recvdLen = 0;
            const bool dataOk = tr.receiveBlocking(rawBuf, 1024, &recvdLen);

            if (dataOk)
            {
                for (size_t i = 0; i < recvdLen; ++i)
                {
                    printf("%c", rawBuf[i]);
                }
                printf(" ");
                fflush(stdout);
            }
        }
    }};

    while (true)
    {
        std::string dataToSend;
        std::getline(std::cin, dataToSend);

        printf("[client] echo: %s\n", dataToSend.c_str());

        tr.sendBlocking((uint8_t *)dataToSend.c_str(), dataToSend.size());
    }

    readerShouldRun = false;
    chatReader.join();

    return 0;
}
