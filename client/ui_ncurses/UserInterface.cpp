#include "UserInterface.hpp"

#include "SecchatClient.hpp"
#include "Utils.hpp"

#include <iomanip>
#include <mutex>
#include <ncurses.h>
#include <sstream>

namespace ui
{

std::mutex gPrintInputFormattedMessagesMutex;
std::vector<std::string> gPrintInputFormattedMessages;

void handleCtrlC(int /*signal*/)
{
    endwin(); // Clean up ncurses
    exit(0);  // Terminate the program
}

void stopUserInterface()
{
    endwin();
    exit(0);
}

static void drawChatWindow( //
    WINDOW *chatWin,
    int chatHeight,
    int /*chatWidth*/)
{
    wclear(chatWin);
    box(chatWin, 0, 0);

    {
        std::lock_guard<std::mutex> lk{gPrintInputFormattedMessagesMutex};
        int numMessages = gPrintInputFormattedMessages.size();

        int startRow = std::max(0, numMessages - chatHeight + 2);
        int y = 1;
        for (int i = startRow, row = 0; i < numMessages && row < chatHeight - 2; ++i, ++row)
        {
            const auto &msg = gPrintInputFormattedMessages[i];
            mvwprintw(chatWin, y + row, 1, "%s", msg.c_str());
        }
    }

    wrefresh(chatWin);
}

static bool initializeChatTUI( //
    WINDOW *&chatWin,
    WINDOW *&inputWin,
    int &chatHeight,
    int &chatWidth)
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    constexpr int kTuiInputTimeoutMs = 1000;
    timeout(kTuiInputTimeoutMs);

    if (!has_colors())
    {
        endwin();
        utils::log("Error: Terminal does not support color.");
        return false;
    }

    start_color();

    init_pair(1, COLOR_WHITE, COLOR_BLUE); // Pair 1 for blue line

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    // Calculate the height of the input and chat windows
    int inputHeight = 3;
    chatHeight = rows - inputHeight - 1;
    chatWidth = cols - 2; // Exclude the borders

    // Create the chat window
    chatWin = newwin(chatHeight, cols, 0, 0);
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

static void scrollbackCleanupIfTooBig()
{
    {
        std::lock_guard<std::mutex> lk{gPrintInputFormattedMessagesMutex};

        constexpr int kMaxScrollbackLines = 100;
        if (gPrintInputFormattedMessages.size() > kMaxScrollbackLines)
        {
            const int toBeErased = (gPrintInputFormattedMessages.size() - kMaxScrollbackLines);
            gPrintInputFormattedMessages.erase(gPrintInputFormattedMessages.begin(),
                                               gPrintInputFormattedMessages.begin() + toBeErased);
        }
    }
}

static void scrollbackAddMessage(const std::string &msg)
{
    std::lock_guard<std::mutex> lk{gPrintInputFormattedMessagesMutex};
    gPrintInputFormattedMessages.push_back(msg);
}

static void runChatTUI( //
    WINDOW *chatWin,
    WINDOW *inputWin,
    int &chatHeight,
    int &chatWidth,
    SecchatClient &client,
    const std::string &joinedRoom,
    const std::string &userName)
{
    const std::string inputFieldPrefix = utils::formatChatMessage(joinedRoom, userName);
    const int inputFieldPrefixSize = inputFieldPrefix.size();

    std::string inputText;
    const int cursorPositionXDefault = 1 + inputFieldPrefixSize;
    int cursorPositionX = cursorPositionXDefault;

    bool tuiShouldRun = true;
    while (tuiShouldRun)
    {

        scrollbackCleanupIfTooBig();

        drawChatWindow(chatWin, chatHeight, chatWidth);

        mvwprintw(inputWin, //
                  1,
                  1,
                  "%s",
                  inputFieldPrefix.c_str());

        // Move the cursor to the input window
        wmove(inputWin, 1, cursorPositionX);
        wrefresh(inputWin);

        int ch = getch();
        if (ch == ERR)
        {
            // timed out
            continue;
        }

        switch (ch)
        {
            case '\n':
                {
                    // special command
                    // TODO: extract "special commands" to some parser
                    const std::string cmdQuit = "/quit";
                    const std::string cmdQuitShort = "/q";
                    if ((inputText == cmdQuit) || (inputText == cmdQuitShort))
                    {
                        tuiShouldRun = false;
                        continue;
                    }

                    // add the message to the chat
                    const std::string formattedMessage = //
                        utils::formatChatMessage(joinedRoom, userName, inputText);
                    scrollbackAddMessage(formattedMessage);

                    const bool sendOk = client.sendMessage(joinedRoom, inputText);
                    if (!sendOk)
                    {
                        std::stringstream ss;
                        ss << "[client] sending ";
                        ss << inputText;
                        ss << " failed...";

                        scrollbackAddMessage(ss.str());
                    }

                    // move cursor back to default
                    cursorPositionX = cursorPositionXDefault;

                    // clear the input window and input text
                    werase(inputWin);
                    box(inputWin, 0, 0);
                    wrefresh(inputWin);
                    inputText.clear();
                }
                break;

            case KEY_BACKSPACE: // fallthrough
            case 127:
                {
                    if (!inputText.empty())
                    {
                        // remove the last character from the input text
                        inputText.pop_back();

                        // move the cursor back and overwrite the character with a space
                        cursorPositionX = (cursorPositionX > cursorPositionXDefault) //
                                              ? (cursorPositionX - 1)
                                              : cursorPositionXDefault;
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
                    if (cursorPositionX > cursorPositionXDefault)
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
                    if ((cursorPositionX < (chatWidth - 1)) && //
                        (cursorPositionX <= ((int)inputText.length() + cursorPositionXDefault - 1)))
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
                    const int textPosition = cursorPositionX - cursorPositionXDefault + 1;
                    inputText.insert(textPosition - 1, 1, static_cast<char>(ch));
                    cursorPositionX++;

                    // Clear and redraw the input window with the updated input text
                    werase(inputWin);
                    box(inputWin, 0, 0);
                    mvwprintw(inputWin, //
                              1,
                              1,
                              "%s%s",
                              inputFieldPrefix.c_str(),
                              inputText.c_str());
                    wrefresh(inputWin);
                }

                break;
        }
    }

    delwin(inputWin);
    delwin(chatWin);
    endwin();
}

bool runChatUserInterface( //
    SecchatClient &client,
    const std::string &joinedRoom,
    const std::string &userName)
{
    WINDOW *chatWin = nullptr;
    WINDOW *inputWin = nullptr;
    int chatHeight = 0;
    int chatWidth = 0;

    const bool tuiStarted = //
        initializeChatTUI(chatWin, inputWin, chatHeight, chatWidth);
    if (!tuiStarted)
    {
        return false;
    }

    runChatTUI( //
        chatWin,
        inputWin,
        chatHeight,
        chatWidth,
        client,
        joinedRoom,
        userName);

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
