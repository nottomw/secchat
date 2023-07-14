#include "SecchatClient.hpp"

#include <chrono>
#include <cstdio>
#include <iostream>
#include <thread>

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

    const bool joined = client.joinRoom(room);
    if (!joined)
    {
        printf("[client] could not join room %s\n", room.c_str());
        return 0;
    }

    // TODO: terminal stuff - display messages on top, prompt bottoms

    printf("[client] now chatting in %s\n", room.c_str());
    while (true)
    {
        printf("[client][%s] > ", room.c_str());
        fflush(stdout);

        std::string message;
        std::getline(std::cin, message);

        const bool sendOk = client.sendMessage(room, message);
        if (!sendOk)
        {
            printf("[client] sending %s failed...\n", message.c_str());
        }
    }

    client.disconnectFromServer();

    return 0;
}
