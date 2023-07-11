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

    DataTransport tr{12345};
    tr.serve();

    printf("Serve returned...");

    uint8_t buf[1024];
    uint32_t recvSize = 0;

    bool recvOk = false;
    do
    {
        recvOk = tr.receiveBlocking(&buf[0], 1024, &recvSize);
    } while (!recvOk);

    if (recvOk)
    {
        printf("Receive done '%s'...\n", buf);
    }
    else
    {
        printf("Receive fail\n");
    }

    // TODO: join threads

    return 0;
}
