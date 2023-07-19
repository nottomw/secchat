#pragma once

#include "Crypto.hpp"
#include "DataTransport.hpp"
#include "Proto.hpp"
#include "WaitQueue.hpp"

#include <condition_variable>

class SecchatClient
{
public:
    SecchatClient(std::vector<std::string> &messageUIScrollback);

    void connectToServer(const std::string &ipAddr, const uint16_t port);
    void disconnectFromServer();

    bool startChat(const std::string &userName);
    bool joinRoom(const std::string &roomName);
    bool sendMessage(const std::string &roomName, const std::string &message);

private:
    DataTransport mTransport;

    bool mReaderShouldRun;
    std::thread mChatReader;

    crypto::KeyAsym mKeyMyAsym;
    crypto::KeyAsymSignature mKeyMyAsymSign;

    crypto::KeyAsym mKeyServerAsym;
    crypto::KeyAsymSignature mKeyServerAsymSign;

    // TODO: should be bound to a specific room
    bool mSymmetricEncryptionReady;
    crypto::KeySym mKeyChatGroup;

    std::string mMyUserName;

    std::vector<std::string> mJoinedRooms;

    std::vector<std::string> &mMessageUIScrollback;

    utils::WaitQueue mWaitQueue;

    void handlePacket( //
        const uint8_t *const data,
        const uint32_t dataLen,
        std::shared_ptr<Session> session);

    void userConnect();
    void handleConnectAck(Proto::Frame &frame);
    void serverJoinRoom(const std::string &roomName);
    void handleChatRoomJoined(Proto::Frame &frame);
    void handleCurrentSymKeyRequest(Proto::Frame &frame);
    void handleMessageToRoom(Proto::Frame &frame);

    void newSymKeyRequested(const std::string &source, const std::string &roomName);
};
