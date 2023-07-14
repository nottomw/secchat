#include "SecchatServer.hpp"

#include "Proto.hpp"
#include "Utils.hpp"

uint32_t SecchatServer::User::mGlobalUserId = 0U;

SecchatServer::SecchatServer()
    : mReaderShouldRun{true}
{
    if (!mCrypto.init())
    {
        printf("Crypto init failed\n");
    }
}

void SecchatServer::start(const uint16_t serverPort)
{
    mTransport.serve(serverPort);

    mTransport.onServerConnect( //
        [&] {
            printf("[server] accepting new connection...\n");
            fflush(stdout);
        });

    mTransport.onDisconnect( //
        [&](std::weak_ptr<Session> session) {
            // TODO: this async session/user collection is problematic and
            // causes mutex hell, maybe this should be transactional in some way

            auto sessPtr = session.lock();
            assert(sessPtr); // this ptr should never be incorrect

            // Remove dropped user from all rooms he joined...
            for (auto &roomIt : mRooms)
            {
                std::lock_guard<std::mutex> lkRoom{roomIt.mRoomMutex};
                auto &joinedUsers = roomIt.mJoinedUsers;

                joinedUsers.erase(  //
                    std::remove_if( //
                        joinedUsers.begin(),
                        joinedUsers.end(),
                        [&](UserId userId) { //
                            User &user = findUserById(userId);
                            auto userSessionPtr = user.mSession.lock();
                            if (*userSessionPtr == *sessPtr)
                            {
                                printf("[server] removing user %s from room %s\n", //
                                       user.mUserName.c_str(),
                                       roomIt.roomName.c_str());

                                return true; // remove
                            }

                            return false; // dont remove
                        }),
                    joinedUsers.end());
            }

            // Remove user...
            uint32_t userCount = 0U;
            {
                std::lock_guard<std::mutex> lk{mUsersMutex};
                mUsers.erase(                      //
                    std::remove_if(mUsers.begin(), //
                                   mUsers.end(),
                                   [&](User &user) { //
                                       auto userSessionPtr = user.mSession.lock();
                                       if (*userSessionPtr == *sessPtr)
                                       {
                                           printf("[server] removing user %s\n", user.mUserName.c_str());
                                           return true; // remove
                                       }

                                       return false; // dont remove
                                   }),
                    mUsers.end());

                userCount = mUsers.size();
            }

            printf("[server] currently %d users active\n", userCount);
        });

    mChatReader = std::thread{[&]() {
        while (mReaderShouldRun)
        {
            uint8_t rawBuf[1024];
            uint32_t recvdLen = 0;
            const auto session = mTransport.receiveBlocking(rawBuf, 1024, &recvdLen);
            auto sessionShared = session.lock();
            if (sessionShared)
            {
                handlePacket(rawBuf, recvdLen, sessionShared);
            }
        }
    }};
}

void SecchatServer::stop()
{
    mReaderShouldRun = false;
    mChatReader.join();
}

SecchatServer::User &SecchatServer::findUserById(const SecchatServer::UserId userId)
{
    std::lock_guard<std::mutex> lk{mUsersMutex};
    for (auto &user : mUsers)
    {
        if (user.id == userId)
        {
            return user;
        }
    }

    assert(nullptr == "findUserById - user not found");
}

void SecchatServer::handlePacket( //
    const uint8_t *const data,
    const uint32_t dataLen,
    std::shared_ptr<Session> session)
{
    auto receivedFrames = Proto::deserialize(data, dataLen);
    for (auto &framesIt : receivedFrames)
    {
        Proto::Payload &payload = framesIt.getPayload();
        switch (payload.type)
        {
            case Proto::PayloadType::kNewUser:
                handleNewUser(framesIt, session);
                break;

            case Proto::PayloadType::kJoinChatRoom:
                handleJoinChatRoom(framesIt, session);
                break;

            default:
                printf("[server] incorrect frame, NOT HANDLED: ");
                utils::printCharactersHex(data, dataLen);
                break;
        }
    }

    // handle sym key exchange -> forward user pub key to all users
    // handle asym key exchange -> forward to all users
    // handle messages -> forward
}

void SecchatServer::handleNewUser( //
    Proto::Frame &frame,
    std::shared_ptr<Session> session)
{
    std::string userName;
    userName.assign((char *)frame.getPayload().payload.get(), frame.getPayload().size);

    const auto existingUser = verifyUserExists(userName);
    if (existingUser)
    {
        // TODO: what if it's same user but new session?
        // Assuming the user identity is validated for now and just overwriting the session.
        User *const user = *existingUser;
        user->mSession = session;

        printf("[server] user %s already exists, DROP (but update the session)\n", userName.c_str());
        return;
    }

    User user;
    user.mUserName = userName;
    user.mSession = session;

    printf("[server] new user created: %s\n", user.mUserName.c_str());

    uint32_t usersCount = 0U;

    {
        std::lock_guard<std::mutex> lk{mUsersMutex};
        mUsers.push_back(std::move(user));
        usersCount = mUsers.size();
    }

    printf("[server] currently %d users active\n", usersCount);

    std::string destination;
    destination.assign(frame.getHeader().source.get(), frame.getHeader().sourceSize);

    // TODO: source should be some kind of address?
    // TODO: reply should assign some ID?

    std::string source{"server"};
    Proto::Frame replyFrame{                               //
                            (uint32_t)source.size(),       // source
                            (uint32_t)destination.size(),  // dest
                            (uint32_t)destination.size()}; // payload - assigned name

    Proto::populateHeader(replyFrame, source, destination);

    Proto::populatePayload( //
        replyFrame,
        Proto::PayloadType::kNewUserIdAssigned,
        (uint8_t *)destination.c_str(),
        destination.size());

    auto replyFrameSer = Proto::serialize(replyFrame);

    const bool sendOk = mTransport.sendBlocking(replyFrameSer.get(), replyFrame.getSize(), session);
    assert(sendOk);
}

void SecchatServer::handleJoinChatRoom( //
    Proto::Frame &frame,
    std::shared_ptr<Session> /*session*/)
{
    Proto::Header &header = frame.getHeader();
    Proto::Payload &payload = frame.getPayload();

    std::string userName;
    userName.assign((char *)header.source.get(), header.sourceSize);

    std::string chatRoomName;
    chatRoomName.assign((char *)payload.payload.get(), payload.size);

    // Find if the user exists
    auto userOk = verifyUserExists(userName);
    if (!userOk)
    {
        printf("[server] user %s requested to join room %s, but user not registered yet, DROP\n", //
               userName.c_str(),
               chatRoomName.c_str());
        return;
    }

    printf("[server] chatroom join requested from user %s, room name: %s\n", //
           userName.c_str(),
           chatRoomName.c_str());

    const User *const user = *userOk; // dereference std::optional
    joinUserToRoom(*user, chatRoomName);
}

void SecchatServer::joinUserToRoom( //
    const SecchatServer::User &user,
    const std::string &roomName)
{
    std::optional<std::reference_wrapper<Room>> room;
    for (auto &roomIt : mRooms)
    {
        if (roomIt.roomName == roomName)
        {
            room = roomIt;
            break;
        }
    }

    if (room)
    {
        std::lock_guard<std::mutex> lkRoom{room->get().mRoomMutex};

        std::optional<UserId> joinedUser;
        for (const auto &joinedUserIDIt : room->get().mJoinedUsers)
        {
            // TODO: compare also identity
            if (joinedUserIDIt == user.id)
            {
                joinedUser = joinedUserIDIt;
                break;
            }
        }

        if (joinedUser)
        {
            printf("[server] room already exists - user already joined, DROP\n");
            return;
        }
        else
        {
            // TODO: should reply with kChatRoomJoined

            room->get().mJoinedUsers.push_back(user.id);
            printf("[server] room already exists - user joined\n");
        }
    }
    else
    {
        Room newRoom;

        {
            std::lock_guard<std::mutex> lkRoom{newRoom.mRoomMutex};
            newRoom.roomName = roomName;
            newRoom.mJoinedUsers.push_back(user.id);

            mRooms.push_back(std::move(newRoom));
        }

        // TODO: should reply with kChatRoomJoined

        printf("[server] new room created, user joined\n");
    }
}

std::optional<SecchatServer::User *> SecchatServer::verifyUserExists(const std::string &userName)
{
    // User identity verification also needed...

    // Maybe should change the vector to map
    {
        std::lock_guard<std::mutex> lk{mUsersMutex};
        for (auto &userIt : mUsers)
        {
            if (userIt.mUserName == userName)
            {
                return &userIt;
            }
        }
    }

    return std::nullopt;
}

SecchatServer::User::User()
    : id{mGlobalUserId++}
{
}

SecchatServer::Room::Room(SecchatServer::Room &&other)
    : roomName{std::move(other.roomName)}
    , mJoinedUsers{std::move(other.mJoinedUsers)}
{
}
