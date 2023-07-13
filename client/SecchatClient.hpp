#pragma once

#include "Crypto.hpp"
#include "DataTransport.hpp"

class SecchatClient{
public:
    SecchatClient();

    void connectToServer(const std::string &ipAddr, const uint16_t port);
    void disconnectFromServer();

    void startChat();

private:
    Crypto mCrypto;
    DataTransport mTransport;

    bool mReaderShouldRun;
    std::thread mChatReader;
};
