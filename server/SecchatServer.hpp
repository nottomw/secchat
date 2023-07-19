#pragma once

#include "Crypto.hpp"
#include "DataTransport.hpp"
#include "Proto.hpp"

#include <optional>

// TODO: persistency - BerkeleyDB (?)

class SecchatServer
{
public:
    SecchatServer();

    void start(const uint16_t serverPort);
    void stop();

private:
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

        crypto::KeyAsymSignature keySign;
        crypto::KeyAsym keyEncrypt;
    };

    std::vector<User> mUsers;

    struct Room
    {
        Room() = default;
        Room(Room &&other);

        bool operator==(const std::string &str);

        std::string roomName;
        std::vector<UserId> mJoinedUsers;
    };

    std::vector<Room> mRooms;

    std::mutex mSessionsToCollectMutex;
    std::vector<Session::IdType> mSessionsToCollect;

    crypto::KeyAsym mKeyMyAsym;
    crypto::KeyAsymSignature mKeyMyAsymSign;

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

    void handleMessageToChatRoom( //
        Proto::Frame &frame,
        std::shared_ptr<Session> session,
        const uint8_t *const rawBuffer);

    // for now "newRoomCreated", should be something nicer
    bool joinUserToRoom( //
        User &user,
        const std::string &roomName,
        bool &newRoomCreated);

    std::optional<User *> verifyUserExists(const std::string &userName);

    bool requestNewSymKeyFromUser( //
        const std::string &roomName,
        SecchatServer::User &userHandle);

    void cleanupDisconnectedUsers();
};
