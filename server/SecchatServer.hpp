#pragma once

#include "Crypto.hpp"
#include "DataTransport.hpp"
#include "Proto.hpp"

#include <optional>

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

    struct User
    {
        std::string mUserName;
        std::weak_ptr<Session> mSession;
    };

    std::vector<User> mUsers;

    struct Room
    {
        std::string roomName;
        std::vector<User> mJoinedUsers; // TODO: unnecessary copy of User - fixme
    };

    std::vector<Room> mRooms;

    void handlePacket( //
        const uint8_t *const data,
        const uint32_t dataLen,
        std::shared_ptr<Session> session);

    void handleNewUser( //
        Proto::Frame &frame,
        std::shared_ptr<Session> session);

    void handleJoinChatRoom( //
        Proto::Frame &frame,
        std::shared_ptr<Session> session);

    void joinUserToRoom(const User &user, const std::string &roomName);

    std::optional<User *> verifyUserExists(const std::string &userName);
};
