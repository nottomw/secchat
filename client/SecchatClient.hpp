#pragma once

#include "Crypto.hpp"
#include "DataTransport.hpp"
#include "Proto.hpp"

#include <condition_variable>

class SecchatClient
{
public:
    SecchatClient();

    void connectToServer(const std::string &ipAddr, const uint16_t port);
    void disconnectFromServer();

    void startChat(const std::string &userName);
    bool joinRoom(const std::string &roomName);
    bool sendMessage(const std::string &roomName, const std::string &message);

private:
    Crypto mCrypto;
    DataTransport mTransport;

    bool mReaderShouldRun;
    std::thread mChatReader;

    using UserPubKey = uint64_t;
    using UserPrivKey = uint64_t;

    UserPrivKey mMyPrivateKey;
    UserPubKey mMyPublicKey;

    std::string mMyUserName;
    std::vector<std::string> mJoinedRooms;

    std::mutex mJoinedCondVarMutex;
    std::condition_variable mJoinedCondVar;

    void handlePacket( //
        const uint8_t *const data,
        const uint32_t dataLen,
        std::shared_ptr<Session> session);

    void serverNewUserAnnounce();
    void serverJoinRoom(const std::string &roomName);
    void handleChatRoomJoined(Proto::Frame &frame);
    void handleMessageToRoom(Proto::Frame &frame);
};
