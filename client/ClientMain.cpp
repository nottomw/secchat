#include "SecchatClient.hpp"
#include "Utils.hpp"

#include <chrono>
#include <cstdio>
#include <iostream>
#include <ncurses.h>
#include <string>
#include <thread>
#include <vector>

// int main(int argc, char **argv)
//{
//    std::string userName{"testUser1"};
//    if (argc >= 2)
//    {
//        userName = argv[1];
//    }

//    std::string room{"testRoom"};
//    if (argc >= 3)
//    {
//        room = argv[2];
//    }

//    utils::log("[client] username: %s, room: %s\n", userName.c_str(), room.c_str());

//    SecchatClient client;
//    client.connectToServer("127.0.0.1", 12345);

//    client.startChat(userName);

//    const bool joined = client.joinRoom(room);
//    if (!joined)
//    {
//        utils::log("[client] could not join room %s\n", room.c_str());
//        return 0;
//    }

//    std::vector<std::string> messages;

//    //    utils::log("[client] now chatting in %s\n", room.c_str());
//    while (true)
//    {
//        //        utils::log("[client][%s] > ", room.c_str());
//        //        fflush(stdout);

//        //        std::string message;
//        //        std::getline(std::cin, message);

//        //        const bool sendOk = client.sendMessage(room, message);
//        //        if (!sendOk)
//        //        {
//        //            utils::log("[client] sending %s failed...\n", message.c_str());
//        //        }
//    }

//    client.disconnectFromServer();

//    return 0;
//}

void handleCtrlC(int signal)
{
    endwin(); // Clean up ncurses
    exit(0);  // Terminate the program
}

static void drawChatWindow( //
    WINDOW *chatWin,
    const std::vector<std::string> &formattedMessages,
    int chatHeight,
    int chatWidth)
{
    wclear(chatWin);
    box(chatWin, 0, 0);

    int numMessages = formattedMessages.size();
    int startRow = std::max(0, numMessages - chatHeight + 2);

    int y = 1;
    for (int i = startRow, row = 0; i < numMessages && row < chatHeight - 2; ++i, ++row)
    {
        const auto &msg = formattedMessages[i];
        mvwprintw(chatWin, y + row, 1, "%s", msg.c_str());
    }

    wrefresh(chatWin);
}

static bool startChatTUI(WINDOW *&chatWin, WINDOW *&inputWin, int *chatHeight, int *chatWidth)
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    if (!has_colors())
    {
        endwin();
        utils::log("Error: Terminal does not support color.\n");
        return false;
    }

    start_color();

    init_pair(1, COLOR_WHITE, COLOR_BLUE); // Pair 1 for blue line

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    // Calculate the height of the input and chat windows
    int inputHeight = 3;
    *chatHeight = rows - inputHeight - 1;
    *chatWidth = cols - 2; // Exclude the borders

    // Create the chat window
    chatWin = newwin(*chatHeight, cols, 0, 0);
    box(chatWin, 0, 0);
    wrefresh(chatWin);

    // Create the input window
    inputWin = newwin(inputHeight, cols, rows - inputHeight, 0);
    box(inputWin, 0, 0);
    wrefresh(inputWin);

    // Create a blue line between the input and chat windows
    attron(COLOR_PAIR(1));
    mvhline(rows - inputHeight - 1, 0, ACS_HLINE, cols);
    attroff(COLOR_PAIR(1));

    // Show the cursor
    curs_set(1);

    return true;
}

int main()
{
    signal(SIGINT, handleCtrlC);

    WINDOW *chatWin = nullptr;
    WINDOW *inputWin = nullptr;
    int chatHeight = 0;
    int chatWidth = 0;

    const bool tuiStarted = startChatTUI(chatWin, inputWin, &chatHeight, &chatWidth);
    if (!tuiStarted)
    {
        return 0;
    }

    std::vector<std::string> formattedMessages;
    std::string inputText;

    int cursorPositionX = 1;

    bool tuiShouldRun = true;
    while (tuiShouldRun)
    {
        drawChatWindow(chatWin, formattedMessages, chatHeight, chatWidth);

        // Move the cursor to the input window
        wmove(inputWin, 1, cursorPositionX);
        wrefresh(inputWin);

        int ch = getch();
        switch (ch)
        {
            case '\n':
                {
                    // special command
                    const std::string cmdQuit = "/quit";
                    const std::string cmdQuitShort = "/q";
                    if ((inputText == cmdQuit) || (inputText == cmdQuitShort))
                    {
                        tuiShouldRun = false;
                    }

                    // Add the message to the chat
                    std::string formattedMessage{"<my_user_name> "};
                    formattedMessage += inputText;
                    formattedMessages.push_back(formattedMessage);

                    // move cursor back
                    cursorPositionX = 1;

                    // Clear the input window and input text
                    werase(inputWin);
                    box(inputWin, 0, 0);
                    wrefresh(inputWin);
                    inputText.clear();
                }
                break;

            case KEY_BACKSPACE:
            case 127:
                {
                    // Handle backspace key
                    if (!inputText.empty())
                    {
                        // Remove the last character from the input text
                        inputText.pop_back();

                        // Move the cursor back and overwrite the character with a space
                        cursorPositionX = (cursorPositionX > 1) ? (cursorPositionX - 1) : 1;
                        int curX, curY;
                        getyx(inputWin, curY, curX);
                        if (curX > 1)
                        {
                            mvwaddch(inputWin, curY, curX - 1, ' ');
                            wmove(inputWin, curY, curX - 1);
                            wrefresh(inputWin);
                        }
                    }
                }
                break;

            case KEY_LEFT:
                {
                    // Move the cursor to the left
                    if (cursorPositionX > 1)
                    {
                        cursorPositionX--;
                        wmove(inputWin, 1, cursorPositionX);
                        wrefresh(inputWin);
                    }
                }
                break;

            case KEY_RIGHT:
                {
                    // Move the cursor to the right
                    if (cursorPositionX < chatWidth - 1 && cursorPositionX <= (int)inputText.length())
                    {
                        cursorPositionX++;
                        wmove(inputWin, 1, cursorPositionX);
                        wrefresh(inputWin);
                    }
                }
                break;

            default:
                // Insert the character at the cursor position within the input text
                if (cursorPositionX <= chatWidth - 1)
                {
                    inputText.insert(cursorPositionX - 1, 1, static_cast<char>(ch));
                    cursorPositionX++;

                    // Clear and redraw the input window with the updated input text
                    werase(inputWin);
                    box(inputWin, 0, 0);
                    mvwprintw(inputWin, 1, 1, "%s", inputText.c_str());
                    wrefresh(inputWin);
                }

                break;
        }
    }

    // Clean up ncurses
    delwin(inputWin);
    delwin(chatWin);
    endwin();

    return 0;
}
