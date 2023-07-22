#pragma once

#include "Utils.hpp"

#include <cassert>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class SecchatClient;

namespace ui
{

void handleCtrlC(int signal);

void stopUserInterface();

bool runChatUserInterface( //
    SecchatClient &client,
    const std::string &joinedRoom,
    const std::string &userName);

void printStr(const std::string &str);

// Print message with UI-specific interface.
template <typename... Ts>
void print(const char *const fmt, Ts... args)
{
    const int strSize = std::snprintf(nullptr, 0, fmt, args...) + 1; // +1 for '\0'
    if (strSize == 0)
    {
        ui::print("[utils] tried to print '%s' which snprintf calculated to size 0", fmt);
        return;
    }

    std::unique_ptr<char[]> buf(new char[strSize]);
    std::snprintf(buf.get(), strSize, fmt, args...);
    std::string str(buf.get(), buf.get() + strSize - 1); // -1 for \0''

    printStr(str);
}

} // namespace ui
