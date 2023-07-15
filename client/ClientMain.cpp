#include "SecchatClient.hpp"
#include "UserInterface.hpp"
#include "Utils.hpp"

#include <chrono>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

int main(int argc, char **argv)
{
    signal(SIGINT, ui::handleCtrlC);

    std::string userName{"test_user"};
    if (argc >= 2)
    {
        userName = argv[1];
    }

    std::string room{"test_room"};
    if (argc >= 3)
    {
        room = argv[2];
    }

    utils::log("[client] username: %s, room: %s\n", userName.c_str(), room.c_str());

    std::vector<std::string> formattedMessagesToUI;

    SecchatClient client{formattedMessagesToUI};
    client.connectToServer("127.0.0.1", 12345);
    client.startChat(userName);

    const bool joined = client.joinRoom(room);
    if (!joined)
    {
        utils::log("[client] could not join room %s\n", room.c_str());
        return 0;
    }

    utils::log("[client] now chatting in %s\n", room.c_str());

    ui::runChatUserInterface( //
        client,
        formattedMessagesToUI,
        room,
        userName);

    utils::log("[client] exiting...");

    client.disconnectFromServer();

    return 0;
}
