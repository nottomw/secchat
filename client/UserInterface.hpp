#pragma once

#include <string>
#include <vector>

class SecchatClient;

namespace ui
{

void handleCtrlC(int signal);

bool runChatUserInterface( //
    SecchatClient &client,
    std::vector<std::string> &formattedMessagesToUI,
    const std::string &joinedRoom,
    const std::string &userName);

} // namespace ui
