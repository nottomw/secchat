#include "UserInterface.hpp"

#include "SecchatClient.hpp"
#include "Utils.hpp"

#include <chrono>
#include <iostream>
#include <thread>

namespace ui
{

void handleCtrlC(int /*signal*/)
{
    exit(0); // Terminate the program
}

bool runChatUserInterface( //
    SecchatClient &client,
    std::vector<std::string> &formattedMessagesToUI,
    const std::string &joinedRoom,
    const std::string &userName)
{
    const std::string prefix = //
        utils::formatChatMessage(joinedRoom, userName);

    bool screenShouldWork = true;
    std::thread screen{[&] {
        while (screenShouldWork)
        {
            // TODO: race cond for "formattedMessagesToUI"
            // needs to be fixed

            for (const auto &msg : formattedMessagesToUI)
            {
                utils::log("%s\n", msg.c_str());
            }

            formattedMessagesToUI.erase(formattedMessagesToUI.begin(), formattedMessagesToUI.end());

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    };

    // In terminal mode we just loop forever,
    // waiting for input...
    while (true)
    {
        std::string inputText;

        std::cout << prefix << " ";
        std::getline(std::cin, inputText);

        const std::string cmdQuit = "/quit";
        const std::string cmdQuitShort = "/q";
        if ((inputText == cmdQuit) || (inputText == cmdQuitShort))
        {
            screenShouldWork = false;
            break;
        }

        const bool sendOk = client.sendMessage(joinedRoom, inputText);
        if (!sendOk)
        {
            utils::log("[client] sending %s failed...\n", inputText.c_str());
        }
    }

    screen.join();

    return true;
}

} // namespace ui
