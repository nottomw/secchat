#include "UserInterface.hpp"

#include "SecchatClient.hpp"
#include "Utils.hpp"

#include <chrono>
#include <iostream>
#include <thread>

namespace ui
{

std::vector<std::string> *gPrintInputFormattedMessages = nullptr;

void handleCtrlC(int /*signal*/)
{
    exit(0); // Terminate the program
}

void stopUserInterface()
{
    // nothing to do
}

void initialize(std::vector<std::string> &formattedMessagesToUI)
{
    gPrintInputFormattedMessages = &formattedMessagesToUI;
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
            // TODO: race cond for "formattedMessagesToUI", needs to be fixed ASAP

            for (const auto &msg : *gPrintInputFormattedMessages)
            {
                utils::log("%s\n", msg.c_str());
            }

            gPrintInputFormattedMessages->erase( //
                gPrintInputFormattedMessages->begin(),
                gPrintInputFormattedMessages->end());

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

void printCharacters( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar)
{
    utils::printCharacters(buffer, bufferSize, lastChar);
}

void printCharactersHex( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar)
{
    utils::printCharactersHex(buffer, bufferSize, lastChar);
}

} // namespace ui
