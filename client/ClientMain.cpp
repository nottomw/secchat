#include "SecchatClient.hpp"

#include <cstdio>

int main(int argc, char **argv)
{

    printf("Hello world from client...\n");

    SecchatClient client;
    client.connectToServer("127.0.0.1", 12345);
    client.startChat();

    // chatting...

    client.disconnectFromServer();

    return 0;
}
