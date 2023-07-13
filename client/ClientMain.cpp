#include "SecchatClient.hpp"

#include <cstdio>

int main(int argc, char **argv)
{
    std::string userName{"testUser1"};
    if (argc >= 2)
    {
        userName = argv[1];
    }

    std::string room{"testRoom"};
    if (argc >= 3)
    {
        room = argv[2];
    }

    printf("[client] username: %s, room: %s\n", userName.c_str(), room.c_str());

    SecchatClient client;
    client.connectToServer("127.0.0.1", 12345);

    client.startChat(userName);
    client.joinRoom(room);

    // chatting...

    client.disconnectFromServer();

    return 0;
}
