#include "UserInterface.hpp"

#include "SecchatClient.hpp"
#include "Utils.hpp"

#include <iomanip>
#include <ncurses.h>
#include <sstream>

namespace ui
{

void handleCtrlC(int /*signal*/)
{
    endwin(); // Clean up ncurses
    exit(0);  // Terminate the program
}

std::vector<std::string> *gPrintInputFormattedMessages = nullptr;

static void drawChatWindow( //
    WINDOW *chatWin,
    const std::vector<std::string> &formattedMessages,
    int chatHeight,
    int /*chatWidth*/)
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
        utils::log("Error: Terminal does not support color.\n");
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

static void runChatTUI( //
    WINDOW *chatWin,
    WINDOW *inputWin,
    int &chatHeight,
    int &chatWidth,
    SecchatClient &client,
    std::vector<std::string> &formattedMessagesToTUI,
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
        // Clear the scrollback if it's too big
        constexpr int kMaxScrollbackLines = 100;
        if (formattedMessagesToTUI.size() > kMaxScrollbackLines)
        {
            const int toBeErased = (formattedMessagesToTUI.size() - kMaxScrollbackLines);
            formattedMessagesToTUI.erase(formattedMessagesToTUI.begin(), formattedMessagesToTUI.begin() + toBeErased);
        }

        drawChatWindow(chatWin, formattedMessagesToTUI, chatHeight, chatWidth);

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
                    formattedMessagesToTUI.push_back(formattedMessage);

                    const bool sendOk = client.sendMessage(joinedRoom, inputText);
                    if (!sendOk)
                    {
                        std::stringstream ss;
                        ss << "[client] sending ";
                        ss << inputText;
                        ss << " failed...\n";

                        formattedMessagesToTUI.push_back(ss.str());
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

    assert(gPrintInputFormattedMessages != nullptr);

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
        *gPrintInputFormattedMessages,
        joinedRoom,
        userName);

    return true;
}

void initialize(std::vector<std::string> &formattedMessagesToUI)
{
    gPrintInputFormattedMessages = &formattedMessagesToUI;
}

void printCharacters( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar)
{
    std::stringstream ss;

    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        const char charToPrint = isprint(buffer[i]) ? buffer[i] : 'X';
        ss << charToPrint;
    }

    if (lastChar != '\0')
    {
        ss << lastChar;
    }

    ui::print("%s", ss.str().c_str());
}

void printCharactersHex( //
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const char lastChar)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (uint32_t i = 0; i < bufferSize; ++i)
    {
        ss << std::setw(2) << static_cast<uint32_t>(buffer[i]) << " ";
    }

    if (lastChar != '\0')
    {
        ss << lastChar;
    }

    ui::print("%s", ss.str().c_str());
}

} // namespace ui
