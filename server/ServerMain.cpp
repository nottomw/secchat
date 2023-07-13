#include "SecchatServer.hpp"

#include <cstdio>

int main()
{
    printf("Hello world from server...\n");

    SecchatServer server;
    server.start(12345);

    while (true)
    {
        // nothing...
    }

    server.stop();

    return 0;
}
