#include "SecchatServer.hpp"

#include "Proto.hpp"
#include "Utils.hpp"

SecchatServer::SecchatServer()
    : mReaderShouldRun{true}
    , mClientsCount{0U}
{
    if (!mCrypto.init())
    {
        printf("Crypto init failed\n");
    }
}

void SecchatServer::start(const uint16_t serverPort)
{
    mTransport.serve(serverPort);

    // TODO: maybe on server connect should provide a way to talk only
    // to the new client (socket? overloaded sendBlocking()?)
    mTransport.onServerConnect( //
        [&] {
            mClientsCount += 1U;
            printf("[server] new connection, clients: %d...\n", mClientsCount);

            fflush(stdout);
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
        printf("[server] user %s already exists, DROP\n", userName.c_str());
        return;
    }

    User user;
    user.mUserName = userName;

    printf("[server] new user created: %s\n", user.mUserName.c_str());

    mUsers.push_back(std::move(user));

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

    joinUserToRoom(*userOk, chatRoomName);
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
        std::optional<User> joinedUser;
        for (const auto &joinedUserIt : room->get().mJoinedUsers)
        {
            // TODO: compare also identity
            if (joinedUserIt.mUserName == user.mUserName)
            {
                joinedUser = joinedUserIt;
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

            room->get().mJoinedUsers.push_back(user);
            printf("[server] room already exists - user joined\n");
        }
    }
    else
    {
        Room newRoom;
        newRoom.roomName = roomName;
        newRoom.mJoinedUsers.push_back(user);

        mRooms.push_back(std::move(newRoom));

        // TODO: should reply with kChatRoomJoined

        printf("[server] new room created, user joined\n");
    }
}

std::optional<SecchatServer::User> SecchatServer::verifyUserExists(const std::string &userName) const
{
    // User identity verification also needed...

    // Maybe should change the vector to map
    for (const auto &userIt : mUsers)
    {
        if (userIt.mUserName == userName)
        {
            return userIt;
        }
    }

    return std::nullopt;
}
