#include "SecchatClient.hpp"

#include <chrono>
#include <iostream>
#include <thread>

SecchatClient::SecchatClient()
    : mCrypto{}
    , mTransport{}
    , mReaderShouldRun{true}
{
    if (!mCrypto.init())
    {
        printf("Crypto init failed\n");
    }
}

void SecchatClient::connectToServer(const std::string &ipAddr, const uint16_t port)
{
    mTransport.connect(ipAddr, port);

    mChatReader = std::thread{//
                              [&]() {
                                  while (mReaderShouldRun)
                                  {
                                      uint8_t rawBuf[1024];
                                      uint32_t recvdLen = 0;
                                      const bool dataOk = mTransport.receiveBlocking(rawBuf, 1024, &recvdLen);

                                      if (dataOk)
                                      {
                                          for (size_t i = 0; i < recvdLen; ++i)
                                          {
                                              printf("%c", rawBuf[i]);
                                          }
                                          printf("\n");
                                          fflush(stdout);
                                      }
                                  }
                              }};
}

void SecchatClient::disconnectFromServer()
{
    mReaderShouldRun = false;
    mChatReader.join();
}

void SecchatClient::startChat()
{
    while (true)
    {
        printf("[client] > ");
        fflush(stdout);

        std::string dataToSend;
        std::getline(std::cin, dataToSend);

        mTransport.sendBlocking((uint8_t *)dataToSend.c_str(), dataToSend.size());
    }
}
