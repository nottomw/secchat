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

    using UserId = uint32_t;

    struct User
    {
        User();
        User(User &&) = default;
        User(const User &) = default;
        User &operator=(const User &) = default;
        User &operator=(User &&) = default;

        static UserId mGlobalUserId;

        UserId id;
        std::string mUserName;
        std::weak_ptr<Session> mSession;
    };

    std::mutex mUsersMutex;
    std::vector<User> mUsers;

    struct Room
    {
        Room() = default;
        Room(Room &&other);

        std::string roomName;
        std::vector<UserId> mJoinedUsers;

        std::mutex mRoomMutex;
    };

    std::vector<Room> mRooms;

    User &findUserById(const UserId userId);

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
