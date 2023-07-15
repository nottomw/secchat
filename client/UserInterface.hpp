#pragma once

#include "Utils.hpp"

#include <cassert>
#include <memory>
#include <string>
#include <vector>

class SecchatClient;

namespace ui
{

void handleCtrlC(int signal);

// must be called before run
void initialize(std::vector<std::string> &formattedMessagesToUI);

bool runChatUserInterface( //
    SecchatClient &client,
    const std::string &joinedRoom,
    const std::string &userName);

// Print message with UI-specific interface.
template <typename... Ts>
void print(const char *const fmt, Ts... args)
{
    // TODO: fix q&d ui print

    extern std::vector<std::string> *gPrintInputFormattedMessages;

    if (gPrintInputFormattedMessages != nullptr)
    {
        int strSize = std::snprintf(nullptr, 0, fmt, args...) + 1; // +1 for '\0'
        assert(strSize > 0);

        std::unique_ptr<char[]> buf(new char[strSize]);
        std::snprintf(buf.get(), strSize, fmt, args...);
        auto str = std::string(buf.get(), buf.get() + strSize - 1); // -1 for \0''

        gPrintInputFormattedMessages->push_back(str);
    }

    // always log too
    utils::log(fmt, args...);
}

} // namespace ui
