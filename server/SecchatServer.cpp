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

    printf("Serve returned...");

    uint8_t buf[1024];
    uint32_t recvSize = 0;

    bool shouldReceive = true;
    while (shouldReceive)
    {
        const bool recvOk = tr.receiveBlocking(&buf[0], 1024, &recvSize);
        if (recvOk)
        {
            printf("Receive done:\n");
            for (uint32_t i = 0; i < recvSize; ++i)
            {
                printf("%c ", buf[i]);
            }
            printf("\n");
        }
    }

    // TODO: join threads

    return 0;
}
