#include "SecchatClient.hpp"

#include <cstdio>

int main()
{
    printf("Hello world from client...\n");

    SecchatClient client;
    client.connectToServer("127.0.0.1", 12345);

    client.startChat("testUser1");

    std::string room{"testRoom"}; // TODO: mem problem fix
    client.joinRoom(room);

    // chatting...

    client.disconnectFromServer();

    return 0;
}
