#pragma once

#include "Crypto.hpp"
#include "DataTransport.hpp"

class SecchatServer
{
public:
    SecchatServer();

    void start(const uint16_t serverPort);
    void stop();

private:
    Crypto mCrypto;
    DataTransport mTransport;

    bool mReaderShouldRun;
    std::thread mChatReader;
};
