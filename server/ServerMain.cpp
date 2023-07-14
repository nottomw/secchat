#include "SecchatServer.hpp"
#include "Utils.hpp"

#include <cstdio>

int main()
{
    utils::log("Hello world from server...\n");

    SecchatServer server;
    server.start(12345);

    while (true)
    {
        // nothing...
    }

    server.stop();

    return 0;
}
