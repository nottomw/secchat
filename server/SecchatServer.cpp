#include "SecchatServer.hpp"

#include "Proto.hpp"
#include "Utils.hpp"

uint32_t SecchatServer::User::mGlobalUserId = 0U;

SecchatServer::SecchatServer()
    : mReaderShouldRun{true}
{
    if (!crypto::init())
    {
        utils::log("Crypto init failed\n");
    }
}

void SecchatServer::start(const uint16_t serverPort)
{
    mTransport.serve(serverPort);

    mTransport.onServerConnect( //
        [&] {
            utils::log("[server] accepting new connection...\n");
            fflush(stdout);
        });

    mTransport.onDisconnect( //
        [&](std::weak_ptr<Session> session) {
            // TODO: this async session/user collection is problematic and
            // causes mutex hell, maybe this should be transactional (some command queue)

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
                                utils::log("[server] removing user %s from room %s\n", //
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
                                           utils::log("[server] removing user %s\n", user.mUserName.c_str());
                                           return true; // remove
                                       }

                                       return false; // dont remove
                                   }),
                    mUsers.end());

                userCount = mUsers.size();
            }

            utils::log("[server] currently %d users active\n", userCount);
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
    // Track the offset of a specific frame in raw buffer so it can be easily
    // forwarded to clients without another serialization.
    const uint8_t *dataOffset = data;

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

            case Proto::PayloadType::k$$$MessageToRoom:
                handleMessageToChatRoom(framesIt, session, dataOffset);
                break;

            default:
                utils::log("[server] incorrect frame, NOT HANDLED: ");
                utils::printCharactersHex(dataOffset, framesIt.getSize());
                break;
        }

        dataOffset += framesIt.getSize();
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

        utils::log("[server] user %s already exists, DROP (but update the session)\n", userName.c_str());
        return;
    }

    User user;
    user.mUserName = userName;
    user.mSession = session;

    utils::log("[server] new user created: %s\n", user.mUserName.c_str());

    uint32_t usersCount = 0U;

    {
        std::lock_guard<std::mutex> lk{mUsersMutex};
        mUsers.push_back(std::move(user));
        usersCount = mUsers.size();
    }

    utils::log("[server] currently %d users active\n", usersCount);

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
    std::shared_ptr<Session> session)
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
        utils::log("[server] user %s requested to join room %s, but user not registered yet, DROP\n", //
                   userName.c_str(),
                   chatRoomName.c_str());
        return;
    }

    utils::log("[server] chatroom join requested from user %s, room name: %s\n", //
               userName.c_str(),
               chatRoomName.c_str());

    const User *const user = *userOk; // dereference std::optional
    const bool joined = joinUserToRoom(*user, chatRoomName);
    if (joined)
    {
        std::string source{"server"};

        Proto::Frame frame{//
                           (uint32_t)source.size(),
                           (uint32_t)userName.size(),
                           (uint32_t)chatRoomName.size()};
        Proto::populateHeader(frame, source, userName);
        Proto::populatePayload( //
            frame,
            Proto::PayloadType::kChatRoomJoined,
            payload.payload.get(), // chat room name
            payload.size);

        auto rawFrame = Proto::serialize(frame);

        const bool sendOk = mTransport.sendBlocking(rawFrame.get(), frame.getSize(), session);
        assert(sendOk);
    }
}

void SecchatServer::handleMessageToChatRoom( //
    Proto::Frame &frame,
    std::shared_ptr<Session> session,
    const uint8_t *const rawBuffer)
{
    const Proto::Header &header = frame.getHeader();
    const Proto::Payload &payload = frame.getPayload();

    std::string userName;
    std::string roomName;
    std::string message;

    userName.assign(header.source.get(), header.sourceSize);
    roomName.assign(header.destination.get(), header.destinationSize);
    message.assign((char *)payload.payload.get(), payload.size);

    const std::string chatMsgFormatted = utils::formatChatMessage(roomName, userName, message);

    utils::log("[server] RX MSG: %s\n", chatMsgFormatted.c_str());

    // TODO: mRooms must be a map...
    auto foundRoom = std::find(mRooms.begin(), mRooms.end(), roomName);

    // TODO: properly handle incorrect room - something strange,
    // probably should drop session
    assert(foundRoom != mRooms.end());

    {
        // TODO: this should be readers-writes (or cleanup mutex hell...)
        std::lock_guard<std::mutex> lk{foundRoom->mRoomMutex};

        // send to all users in this chat room
        for (const auto &userInRoomId : foundRoom->mJoinedUsers)
        {
            const User &user = findUserById(userInRoomId);
            const auto userInRoomSession = user.mSession.lock();
            assert(userInRoomSession); // should never be invalid ptr unless internal userlist is corrupted

            if (*userInRoomSession == *session)
            {
                // If this is the session that we just got the message from,
                // do not echo unnecessarily back.
                continue;
            }

            const bool sendOk = mTransport.sendBlocking(rawBuffer, frame.getSize(), userInRoomSession);
            assert(sendOk);
        }
    }
}

bool SecchatServer::joinUserToRoom( //
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
            utils::log("[server] room already exists - user already joined, DROP\n");
            return true;
        }
        else
        {
            room->get().mJoinedUsers.push_back(user.id);
            utils::log("[server] room already exists - user joined\n");

            return true;
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

        utils::log("[server] new room created, user joined\n");

        return true;
    }

    return false;
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

bool SecchatServer::Room::operator==(const std::string &str)
{
    return (str == roomName);
}
