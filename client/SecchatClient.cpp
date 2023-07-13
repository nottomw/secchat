#include "SecchatClient.hpp"

#include "Proto.hpp"
#include "Utils.hpp"

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

void SecchatClient::startChat(const std::string &userName)
{
    mMyUserName = userName;

    // If this is first user to join the room, he is considered the room owner:
    // - owner generates asymetric group chat key

    // When new user joins:
    // - new user sends pub key to the server
    // - randomly selected user (usr1) is requested to send room key to new user
    // - usr1 encrypts group chat key with pub key
    // - usr1 sends the encrypted group chat key to new user

    // send "new user"
    // receive my ID

    // send "join chat room"
    // receive success/failure

    serverNewUserAnnounce();
}

void SecchatClient::joinRoom(const std::string &roomName)
{
    serverJoinRoom(roomName);

    // TODO: wait until join confirmed or denied
    std::this_thread::sleep_for(std::chrono::seconds(2));
    mJoinedRooms.push_back(roomName);

    while (true)
    {
        printf("[client] > ");
        fflush(stdout);

        std::string dataToSend;
        std::getline(std::cin, dataToSend);

        mTransport.sendBlocking((uint8_t *)dataToSend.c_str(), dataToSend.size());
    }
}

void SecchatClient::serverNewUserAnnounce()
{
    // TODO: mem access error
    // Proto::Header header = Proto::createHeader(mMyUserName, "testdestserver");
    std::string dest{"testdestserver"};
    Proto::Header header = Proto::createHeader(mMyUserName, dest);

    // TODO: this payload should contain user name & public key
    Proto::Payload payload = Proto::createPayload( //
        Proto::PayloadType::kNewUser,
        (uint8_t *)mMyUserName.c_str(), // ugly cast
        mMyUserName.size());

    Proto::Frame frame = Proto::createFrame(header, payload);

    std::shared_ptr<uint8_t[]> buffer = //
        std::shared_ptr<uint8_t[]>(new uint8_t[frame.getSize()]);

    const bool serOk = Proto::serialize(frame, buffer);
    assert(serOk);

    mTransport.sendBlocking(buffer.get(), frame.getSize());
}

void SecchatClient::serverJoinRoom(const std::string &roomName)
{
    Proto::Header header = Proto::createHeader(mMyUserName, roomName);

    Proto::Payload payload = Proto::createPayload( //
        Proto::PayloadType::kJoinChatRoom,
        (uint8_t *)roomName.c_str(), // ugly cast
        roomName.size());

    Proto::Frame frame = Proto::createFrame(header, payload);

    std::shared_ptr<uint8_t[]> buffer = //
        std::shared_ptr<uint8_t[]>(new uint8_t[frame.getSize()]);

    const bool serOk = Proto::serialize(frame, buffer);
    assert(serOk);

    printf("Sending room join request\n");
    utils::printCharacters(buffer.get(), frame.getSize());
    fflush(stdout);

    mTransport.sendBlocking(buffer.get(), frame.getSize());
}
