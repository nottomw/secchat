#include "SecchatClient.hpp"
#include "Utils.hpp"

#include <chrono>
#include <cstdio>
#include <iostream>
#include <ncurses.h>
#include <thread>

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

#include <iostream>
#include <ncurses.h>
#include <string>
#include <vector>

// Structure to represent a chat message
struct ChatMessage
{
    std::string sender;
    std::string message;
};

// Function to draw the chat window
void drawChatWindow(WINDOW *chatWin, const std::vector<ChatMessage> &messages, int chatHeight, int chatWidth)
{
    wclear(chatWin);
    box(chatWin, 0, 0);

    int numMessages = messages.size();
    int startRow = std::max(0, numMessages - chatHeight + 2);

    int y = 1;
    for (int i = startRow, row = 0; i < numMessages && row < chatHeight - 2; ++i, ++row)
    {
        const auto &msg = messages[i];
        mvwprintw(chatWin, y + row, 1, "<%s> %s", msg.sender.c_str(), msg.message.c_str());
    }

    wrefresh(chatWin);
}

void handleCtrlC(int signal)
{
    endwin(); // Clean up ncurses
    exit(0);  // Terminate the program
}

int main()
{
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    // Check if the terminal supports color
    if (!has_colors())
    {
        endwin();
        std::cerr << "Error: Terminal does not support color." << std::endl;
        return 1;
    }

    // Start color mode
    start_color();

    // Define color pairs
    init_pair(1, COLOR_WHITE, COLOR_BLUE); // Pair 1 for blue line

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    // Calculate the height of the input and chat windows
    int inputHeight = 3;
    int chatHeight = rows - inputHeight - 1;
    int chatWidth = cols - 2; // Exclude the borders

    // Create the chat window
    WINDOW *chatWin = newwin(chatHeight, cols, 0, 0);
    box(chatWin, 0, 0);
    wrefresh(chatWin);

    // Create the input window
    WINDOW *inputWin = newwin(inputHeight, cols, rows - inputHeight, 0);
    box(inputWin, 0, 0);
    wrefresh(inputWin);

    // Create a blue line between the input and chat windows
    attron(COLOR_PAIR(1));
    mvhline(rows - inputHeight - 1, 0, ACS_HLINE, cols);
    attroff(COLOR_PAIR(1));

    std::vector<ChatMessage> messages;
    std::string inputText; // Stores the user's input

    int cursorX = 1; // Stores the cursor position within the input window

    bool running = true;
    curs_set(1);

    signal(SIGINT, handleCtrlC);

    // Main loop
    while (running)
    {
        drawChatWindow(chatWin, messages, chatHeight, chatWidth);

        // Move the cursor to the input window
        wmove(inputWin, 1, cursorX);
        wrefresh(inputWin);

        int ch = getch();
        switch (ch)
        {
            case 'q':
                running = false;
                break;
            case '\n':
                {
                    // Add the message to the chat
                    messages.push_back({"User", inputText});

                    // Clear the input window and input text
                    werase(inputWin);
                    box(inputWin, 0, 0);
                    wrefresh(inputWin);
                    inputText.clear();

                    break;
                }
            case KEY_BACKSPACE:
            case 127:
                {
                    // Handle backspace key
                    if (!inputText.empty())
                    {
                        // Remove the last character from the input text
                        inputText.pop_back();

                        // Move the cursor back and overwrite the character with a space
                        int curX, curY;
                        getyx(inputWin, curY, curX);
                        if (curX > 1)
                        {
                            mvwaddch(inputWin, curY, curX - 1, ' ');
                            wmove(inputWin, curY, curX - 1);
                            wrefresh(inputWin);
                        }
                    }

                    break;
                }

            case KEY_LEFT:
                {
                    // Move the cursor to the left
                    if (cursorX > 1)
                    {
                        cursorX--;
                        wmove(inputWin, 1, cursorX);
                        wrefresh(inputWin);
                    }

                    break;
                }
            case KEY_RIGHT:
                {
                    // Move the cursor to the right
                    if (cursorX < chatWidth - 1 && cursorX <= (int)inputText.length())
                    {
                        cursorX++;
                        wmove(inputWin, 1, cursorX);
                        wrefresh(inputWin);
                    }

                    break;
                }
            default:
                // Insert the character at the cursor position within the input text
                if (cursorX <= chatWidth - 1)
                {
                    inputText.insert(cursorX - 1, 1, static_cast<char>(ch));
                    cursorX++;

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
