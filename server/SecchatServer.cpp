#include "SecchatServer.hpp"

#include "Proto.hpp"
#include "Utils.hpp"

uint32_t SecchatServer::User::mGlobalUserId = 0U;

SecchatServer::SecchatServer()
    : mReaderShouldRun{true}
{
    if (!crypto::init())
    {
        utils::log("[server] crypto init failed\n");
        assert(false); // fatal error...
    }

    utils::log("[server] -- crypto keys begin --\n");
    utils::log("[server] crypto: generatic signing key pair, pub:\n");
    mKeyMyAsymSign = crypto::keygenAsymSign();
    utils::printCharactersHex(mKeyMyAsymSign.mKeyPub, crypto::kPubKeySignatureByteCount);

    utils::log("[server] crypto: generatic encrypting key pair, pub:\n");
    mKeyMyAsym = crypto::keygenAsym();
    utils::printCharactersHex(mKeyMyAsym.mKeyPub, crypto::kPubKeyByteCount);

    utils::log("[server] -- crypto keys end --\n");
}

void SecchatServer::start(const uint16_t serverPort)
{
    mTransport.serve(serverPort);

    mTransport.onServerConnect( //
        [&] { utils::log("[server] accepting new connection...\n"); });

    mTransport.onDisconnect( //
        [&](std::weak_ptr<Session> session) {
            auto sessPtr = session.lock();
            assert(sessPtr); // this ptr should never be incorrect

            {
                std::lock_guard<std::mutex> lk{mSessionsToCollectMutex};
                mSessionsToCollect.push_back(sessPtr->getId());
            }
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

            cleanupDisconnectedUsers();
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
        // TODO: would be good to do some buffer/frame size verification here or in deserialization...

        Proto::Payload &payload = framesIt.getPayload();
        switch (payload.type)
        {
            case Proto::PayloadType::kUserConnect:
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
}

void SecchatServer::handleNewUser( //
    Proto::Frame &frame,
    std::shared_ptr<Session> session)
{
    Proto::Payload &payload = frame.getPayload();
    const uint32_t payloadSize = payload.size;

    Proto::PayloadUserConnect newUserFrame = //
        Proto::deserializeUserConnect(payload.payload.get(), payloadSize);

    utils::log("[server] received pubsign/pub keys from %s\n", newUserFrame.userName.c_str());
    utils::log("[server] client sign pubkey:\n");
    utils::printCharactersHex(newUserFrame.pubSignKey, crypto::kPubKeySignatureByteCount);

    utils::log("[server] client encrypt pubkey:\n");
    utils::printCharactersHex(newUserFrame.pubEncryptKey, crypto::kPubKeyByteCount);

    crypto::KeyAsym userEncryptionPubKey;

    const auto existingUser = verifyUserExists(newUserFrame.userName);
    if (existingUser)
    {
        // TODO: If this is a existing user, verify the pubsign/pub keys match!!!
        // TODO: if this is a existing user, and pubkeys OK, reply with connect ack, otherwise drop

        // for now just overwriting the session
        User *const user = *existingUser;
        user->mSession = session;

        userEncryptionPubKey = user->keyEncrypt;

        utils::log("[server] user %s already exists (for now update the session)\n", newUserFrame.userName.c_str());
    }
    else
    {
        User user;
        user.mUserName = newUserFrame.userName;
        user.mSession = session;

        memcpy(user.keySign.mKeyPub, newUserFrame.pubSignKey, crypto::kPubKeySignatureByteCount);
        memcpy(user.keyEncrypt.mKeyPub, newUserFrame.pubEncryptKey, crypto::kPubKeyByteCount);

        userEncryptionPubKey = user.keyEncrypt;

        uint32_t usersCount = 0U;

        mUsers.push_back(std::move(user));
        usersCount = mUsers.size();

        utils::log("[server] new user created: %s, pubsign/pub keys received\n", newUserFrame.userName.c_str());
        utils::log("[server] currently %d users active\n", usersCount);
    }

    // reply with server's pubsign/pub keys (encrypted with users's pub key)

    std::string source{"server"};
    std::string destination = newUserFrame.userName;

    Proto::Frame replyFrame;

    Proto::populateHeader(replyFrame, source, destination);

    Proto::populatePayloadUserConnectAck( //
        replyFrame,
        mKeyMyAsymSign,
        mKeyMyAsym,
        userEncryptionPubKey);

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

    // TODO: on join user should be "quarantined" for a couple for seconds, so
    // the other users won't message anything to unknown user

    const User *const user = *userOk; // dereference std::optional
    const bool joined = joinUserToRoom(*user, chatRoomName);
    if (joined)
    {
        // TODO: broadcast the pubsign/pub keys to other users on room join

        std::string source{"server"};

        Proto::Frame frame;

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

    // send to all users in this chat room
    for (const auto &userInRoomId : foundRoom->mJoinedUsers)
    {
        const User &user = findUserById(userInRoomId);
        const auto userInRoomSession = user.mSession.lock();
        if (!userInRoomSession)
        {
            // invalid session - will be collected soon
            continue;
        }

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
        std::optional<UserId> joinedUser;
        for (const auto &joinedUserIDIt : room->get().mJoinedUsers)
        {
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
            newRoom.roomName = roomName;
            newRoom.mJoinedUsers.push_back(user.id);

            mRooms.push_back(std::move(newRoom));
        }

        // TODO: new room - request asym key generation immediately

        utils::log("[server] new room created, user joined\n");

        return true;
    }

    return false;
}

std::optional<SecchatServer::User *> SecchatServer::verifyUserExists(const std::string &userName)
{
    // Maybe should change the vector to map
    for (auto &userIt : mUsers)
    {
        if (userIt.mUserName == userName)
        {
            return &userIt;
        }
    }

    return std::nullopt;
}

void SecchatServer::cleanupDisconnectedUsers()
{
    {
        std::lock_guard<std::mutex> lk{mSessionsToCollectMutex};
        if (mSessionsToCollect.size() == 0)
        {
            return; // nothing to do
        }

        for (const auto invalidatedSessionId : mSessionsToCollect)
        {
            // Remove dropped user from all rooms he joined...
            for (auto &roomIt : mRooms)
            {
                auto &joinedUsers = roomIt.mJoinedUsers;

                joinedUsers.erase(  //
                    std::remove_if( //
                        joinedUsers.begin(),
                        joinedUsers.end(),
                        [&](UserId userId) { //
                            User &user = findUserById(userId);
                            auto userSessionPtr = user.mSession.lock();

                            if ((!userSessionPtr) || //
                                (userSessionPtr->getId() == invalidatedSessionId))
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
            mUsers.erase(                      //
                std::remove_if(mUsers.begin(), //
                               mUsers.end(),
                               [&](User &user) { //
                                   auto userSessionPtr = user.mSession.lock();

                                   if ((!userSessionPtr) || //
                                       (userSessionPtr->getId() == invalidatedSessionId))
                                   {
                                       utils::log("[server] removing user %s\n", user.mUserName.c_str());
                                       return true; // remove
                                   }

                                   return false; // dont remove
                               }),
                mUsers.end());

            utils::log("[server] currently %d users active\n", mUsers.size());
        }

        mSessionsToCollect.clear();
    }
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
