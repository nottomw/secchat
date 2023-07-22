#include "UserInterface.hpp"

#include "SecchatClient.hpp"
#include "Utils.hpp"

#include <chrono>
#include <iostream>
#include <mutex>
#include <thread>

namespace ui
{

std::mutex gPrintInputFormattedMessagesMutex;
std::vector<std::string> gPrintInputFormattedMessages;

void handleCtrlC(int /*signal*/)
{
    exit(0); // Terminate the program
}

void stopUserInterface()
{
    // nothing to do
}

bool runChatUserInterface( //
    SecchatClient &client,
    const std::string &joinedRoom,
    const std::string &userName)
{
    const std::string prefix = //
        utils::formatChatMessage(joinedRoom, userName);

    bool screenShouldWork = true;
    std::thread screen{[&] {
        while (screenShouldWork)
        {
            {
                std::lock_guard<std::mutex> lk{gPrintInputFormattedMessagesMutex};

                for (const auto &msg : gPrintInputFormattedMessages)
                {
                    utils::log("%s", msg.c_str());
                }

                gPrintInputFormattedMessages.clear();
            }

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
            utils::log("[client] sending %s failed...", inputText.c_str());
        }
    }

    screen.join();

    return true;
}

void printStr(const std::string &str)
{
    {
        std::lock_guard<std::mutex> lk{gPrintInputFormattedMessagesMutex};
        gPrintInputFormattedMessages.push_back(str);
    }
}

} // namespace ui
