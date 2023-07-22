#include "SecchatServer.hpp"

#include "Proto.hpp"
#include "Utils.hpp"

uint32_t SecchatServer::User::mGlobalUserId = 0U;

SecchatServer::SecchatServer()
    : mReaderShouldRun{true}
{
    if (!crypto::init())
    {
        utils::log("[server] crypto init failed");
        assert(false); // fatal error...
    }

    mKeyMyAsymSign = crypto::keygenAsymSign();
    mKeyMyAsym = crypto::keygenAsym();

    const std::string keySignPubStrHex = utils::formatCharactersHex(mKeyMyAsymSign.mKeyPub, 5);
    const std::string keyEncrPubStrHex = utils::formatCharactersHex(mKeyMyAsym.mKeyPub, 5);

    utils::log("[server] SERVERS CRYPTO KEY: sign pub key: [ %s ]", keySignPubStrHex.c_str());
    utils::log("[server] SERVERS CRYPTO KEY: encr pub key: [ %s ]", keyEncrPubStrHex.c_str());
}

void SecchatServer::start(const uint16_t serverPort)
{
    mTransport.serve(serverPort);

    mTransport.onServerConnect( //
        [&] { utils::log("[server] accepting new connection..."); });

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

std::optional<SecchatServer::User *> SecchatServer::findUserByName(const std::string &userName)
{
    for (auto &user : mUsers)
    {
        if (user.mUserName == userName)
        {
            return &user;
        }
    }

    return std::nullopt;
}

std::optional<SecchatServer::Room *> SecchatServer::findRoomByName(const std::string &roomName)
{
    for (auto &it : mRooms)
    {
        if (it.roomName == roomName)
        {
            return &it;
        }
    }

    return std::nullopt;
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
            case Proto::PayloadType::kUserConnect:
                handleNewUser(framesIt, session);
                break;

            case Proto::PayloadType::kChatRoomJoin:
                handleJoinChatRoom(framesIt, session);
                break;

            case Proto::PayloadType::k$$$MessageToRoom:
                handleMessageToChatRoom(framesIt, session, dataOffset);
                break;

            case Proto::PayloadType::kChatGroupSymKeyRequest:
                handleChatGroupSymKeyRequest(framesIt);
                break;

            case Proto::PayloadType::kChatGroupSymKeyResponse:
                handleChatGroupSymKeyResponse(framesIt, dataOffset);
                break;

            default:
                const std::string invalidFrameStrHex = //
                    utils::formatCharactersHex(data, dataLen);
                utils::log("[server] received incorrect frame, drop: [%s]",
                           invalidFrameStrHex.c_str());
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

    const std::string signKeyHex = utils::formatCharactersHex(newUserFrame.pubSignKey, 5);
    const std::string encryptKeyHex = utils::formatCharactersHex(newUserFrame.pubEncryptKey, 5);
    utils::log("[server] received user %s pubsign [ %s ] and pub encrypt [ %s ] keys", //
               newUserFrame.userName.c_str(),
               signKeyHex.c_str(),
               encryptKeyHex.c_str());

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

        utils::log("[server] user %s already exists (for now update the session)",
                   newUserFrame.userName.c_str());
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

        utils::log("[server] new user created: %s, pubsign/pub keys received",
                   newUserFrame.userName.c_str());
        utils::log("[server] currently %d users active", usersCount);
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

    const std::string userName{(char *)header.source.get(), header.sourceSize};

    // Find if the user exists
    auto userOk = verifyUserExists(userName);
    if (!userOk)
    {
        utils::log(
            "[server] user %s requested to join some room, but user not registered yet, DROP", //
            userName.c_str());
        return;
    }

    User *const userHandle = *userOk; // dereference std::optional

    auto decrypted = crypto::asymDecrypt( //
        mKeyMyAsym,
        payload.payload.get(),
        payload.size);
    // TODO: there should be a option to check if decryption OK

    auto nonsignedDataOpt = crypto::signedVerify( //
        userHandle->keySign,
        decrypted.data.get(),
        decrypted.dataSize);
    if (!nonsignedDataOpt)
    {
        utils::log("[server] signature verification failed, source: %s", userName.c_str());
        return;
    }

    crypto::NonsignedData &nonsignedData = *nonsignedDataOpt;

    Proto::PayloadJoinReqAck join = //
        Proto::deserializeJoinReqAck(nonsignedData.data.get(), nonsignedData.dataSize);

    utils::log("[server] chatroom join requested from user %s, room name: %s", //
               userName.c_str(),
               join.roomName.c_str());

    // TODO: quarantine: on join user should be "quarantined" for a couple of
    // seconds, so the other users won't message anything to unknown user

    bool newRoomCreated = false;
    const bool joined = joinUserToRoom(*userHandle, join.roomName, newRoomCreated);
    if (joined)
    {
        std::string source{"server"};

        // if new room creation - request sym key generate too
        if (newRoomCreated)
        {
            utils::log("[server] new room created, requesting sym key generation from user %s", //
                       userName.c_str());
        }

        Proto::Frame frame;
        Proto::populateHeader(frame, source, userName);
        Proto::populatePayloadChatRoomJoinOrAck( //
            frame,
            join.roomName,
            mKeyMyAsymSign,
            userHandle->keyEncrypt,
            true,
            newRoomCreated);

        auto rawFrame = Proto::serialize(frame);

        const bool sendOk = mTransport.sendBlocking(rawFrame.get(), frame.getSize(), session);
        assert(sendOk);

        if (newRoomCreated == false)
        {
            // user just joined new room, send out his keys to all and all keys to him
            userJoinedPubKeysExchange(*userHandle, join.roomName);
        }

        // TODO: broadcast the pubsign/pub keys to other users on room join
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

    userName.assign(header.source.get(), header.sourceSize);
    roomName.assign(header.destination.get(), header.destinationSize);

    const auto msgStr = utils::formatCharacters(payload.payload.get(), payload.size);
    utils::log("[server] RX MSG: [%s]<%s>: %s", //
               roomName.c_str(),
               userName.c_str(),
               msgStr.c_str());

    // TODO: mRooms must be a map...
    auto foundRoom = std::find(mRooms.begin(), mRooms.end(), roomName);

    // if room not found probably have to drop session - something strange is happening
    assert(foundRoom != mRooms.end());

    // send to all users in this chat room
    for (const auto &userInRoomId : foundRoom->mJoinedUsers)
    {
        const User &user = findUserById(userInRoomId);
        const auto userInRoomSession = user.mSession;
        if (*userInRoomSession == *session)
        {
            // If this is the session that we just got the message from,
            // do not echo unnecessarily back.
            continue;
        }

        // TODO: should modify the "destination" in header here

        const bool sendOk = mTransport.sendBlocking(rawBuffer, frame.getSize(), userInRoomSession);
        assert(sendOk);
    }
}

void SecchatServer::handleChatGroupSymKeyRequest( //
    Proto::Frame &frame)
{
    Proto::Header &header = frame.getHeader();
    Proto::Payload &payload = frame.getPayload();

    const std::string source{header.source.get(), header.sourceSize};
    utils::log("[server] received sym key request from %s", source.c_str());

    auto userOk = verifyUserExists(source);
    if (!userOk)
    {
        utils::log("[server] user %s does not exist, drop", source.c_str());
        return;
    }

    User *userHandleSource = *userOk;

    auto decrypted = //
        crypto::asymDecrypt(mKeyMyAsym, payload.payload.get(), payload.size);

    auto unsignedPay =
        crypto::signedVerify(userHandleSource->keySign, decrypted.data.get(), decrypted.dataSize);
    if (!unsignedPay)
    {
        utils::log("[server] signature verification failed for sym key request, drop");
        return;
    }

    const std::string roomName{(char *)unsignedPay->data.get(), unsignedPay->dataSize};

    auto roomHandleOpt = findRoomByName(roomName);
    if (!roomHandleOpt)
    {
        utils::log("[server] room %s not found, drop", roomName.c_str());
        return;
    }

    auto roomHandle = *roomHandleOpt;

    // at this point at least a single user should be joined
    assert(roomHandle->mJoinedUsers.size() != 0);

    // find user to send the key request to
    // for now just grab the first user in sequence that is not just joined user
    User *requestDestinationUserId = nullptr;
    for (auto &joinedUsersId : roomHandle->mJoinedUsers)
    {
        User &joinedUser = findUserById(joinedUsersId);
        if (joinedUser.mUserName == source)
        {
            // cant request sym key from myself...
            continue;
        }

        requestDestinationUserId = &joinedUser; // found one
        break;
    }

    utils::log("[server] request sym key for room %s from user %s", //
               roomName.c_str(),
               source.c_str());

    if (requestDestinationUserId == nullptr)
    {
        // looks like just joined user is the only one here,
        // the new sym key generation needs to requested from him
        utils::log("[server] user %s is the only user in this room, drop request", source.c_str());
        return;
    }

    Proto::Frame frameSymKeyRequest;
    Proto::populateHeader(frameSymKeyRequest, source, requestDestinationUserId->mUserName);

    Proto::populatePayloadCurrentSymKeyRequest( //
        frameSymKeyRequest,
        roomName,
        mKeyMyAsymSign,
        requestDestinationUserId->keyEncrypt);

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frameSymKeyRequest);
    assert(buffer);

    const bool sendOk =          //
        mTransport.sendBlocking( //
            buffer.get(),
            frameSymKeyRequest.getSize(),
            requestDestinationUserId->mSession);

    if (sendOk == false)
    {
        utils::log("[server] sym key request - failed - user disconnected?...");
    }
}

void SecchatServer::handleChatGroupSymKeyResponse( //
    Proto::Frame &frame,
    const uint8_t *const rawBuffer)
{
    Proto::Header &header = frame.getHeader();

    const std::string source{(char *)header.source.get(), header.sourceSize};
    const std::string dest{(char *)header.destination.get(), header.destinationSize};

    utils::log("[server] forwarding sym key from user %s to user %s", //
               source.c_str(),
               dest.c_str());

    // find the destination users's session
    auto userHandleOpt = findUserByName(dest);
    if (!userHandleOpt)
    {
        utils::log("[server] user %s not found, drop", dest.c_str());
        return;
    }

    User *userHandle = *userHandleOpt;

    mTransport.sendBlocking(rawBuffer, frame.getSize(), userHandle->mSession);
}

bool SecchatServer::joinUserToRoom( //
    SecchatServer::User &user,
    const std::string &roomName,
    bool &newRoomCreated)
{
    newRoomCreated = false;

    auto roomOpt = findRoomByName(roomName);
    if (roomOpt)
    {
        Room *const room = *roomOpt;

        std::optional<UserId> joinedUser;
        for (const auto &joinedUserIDIt : room->mJoinedUsers)
        {
            if (joinedUserIDIt == user.id)
            {
                joinedUser = joinedUserIDIt;
                break;
            }
        }

        if (joinedUser)
        {
            utils::log("[server] room already exists - user already joined, DROP");
            return true;
        }
        else
        {
            room->mJoinedUsers.push_back(user.id);
            utils::log("[server] room already exists - user joined");

            const uint32_t joinedUsersCount = room->mJoinedUsers.size();
            if (joinedUsersCount == 1)
            {
                utils::log("[server] just joined user is the only user in this room");
                utils::log("[server] the room was already created, but for now simulating new room "
                           "create");

                // TODO: should be handled nicer
                newRoomCreated = true;
            }

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

        newRoomCreated = true;

        return true;
    }

    return false;
}

void SecchatServer::userJoinedPubKeysExchange( //
    User &userHandle,
    const std::string &roomName)
{
    auto roomOpt = findRoomByName(roomName);
    assert(roomOpt); // room must exist now

    // First, send the user's keys to all joined members...
    Room *const room = *roomOpt;
    for (auto &alreadyJoinedUserId : room->mJoinedUsers)
    {
        User &alreadyJoinedUser = findUserById(alreadyJoinedUserId);

        if (alreadyJoinedUser.mUserName != userHandle.mUserName)
        {
            // do the key exchange between just joined users and other users

            // send just joined user's keys to other users in chat
            sendUserKeysToUser( //
                alreadyJoinedUser.keySign,
                alreadyJoinedUser.keyEncrypt,
                alreadyJoinedUser.mUserName,
                userHandle.mUserName,
                &userHandle);

            // sent the other user's keys to just joined user
            sendUserKeysToUser( //
                userHandle.keySign,
                userHandle.keyEncrypt,
                userHandle.mUserName,
                alreadyJoinedUser.mUserName,
                &alreadyJoinedUser);
        }
    }
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

bool SecchatServer::requestNewSymKeyFromUser( //
    const std::string &roomName,
    SecchatServer::User &userHandle)
{
    Proto::Frame frame;
    Proto::populateHeader(frame, "server", roomName);

    Proto::populatePayloadNewSymKeyRequest( //
        frame,
        roomName,
        mKeyMyAsymSign,
        userHandle.keyEncrypt);

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    assert(buffer);

    const bool sendOk =          //
        mTransport.sendBlocking( //
            buffer.get(),
            frame.getSize(),
            userHandle.mSession);

    return sendOk;
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
                            auto userSessionPtr = user.mSession;
                            if ((!userSessionPtr) || //
                                (userSessionPtr->getId() == invalidatedSessionId))
                            {
                                utils::log("[server] removing user %s from room %s", //
                                           user.mUserName.c_str(),
                                           roomIt.roomName.c_str());

                                return true; // remove
                            }

                            return false; // dont remove
                        }),
                    joinedUsers.end());

                if (joinedUsers.size() == 0)
                {
                    utils::log("[server] the room %s is now empty, should remove?",
                               roomIt.roomName.c_str());
                }
            }

            // TODO: persistency - user should not be removed here, instead
            // the already created user should keep hold of he's keys and
            // resend them on creation of new user.

            mUsers.erase(                      //
                std::remove_if(mUsers.begin(), //
                               mUsers.end(),
                               [&](User &user) { //
                                   auto userSessionPtr = user.mSession;
                                   if ((!userSessionPtr) || //
                                       (userSessionPtr->getId() == invalidatedSessionId))
                                   {
                                       utils::log("[server] removing user %s",
                                                  user.mUserName.c_str());
                                       return true; // remove
                                   }

                                   return false; // dont remove
                               }),
                mUsers.end());

            utils::log("[server] currently %d users active", mUsers.size());
        }

        mSessionsToCollect.clear();
    }
}

void SecchatServer::sendUserKeysToUser( //
    const crypto::KeyAsymSignature &keysToSendSign,
    const crypto::KeyAsym &keysToSendEncrypt,
    const std::string &userNameSrc,
    const std::string &userNameDest,
    const SecchatServer::User *const userHandleDest)
{
    const SecchatServer::User *userHandleDestFound = userHandleDest;
    if (userHandleDest == nullptr)
    {
        assert(nullptr == "TODO TODO TODO TODO TODO TODO TODO");
        // have to find dest user by name
    }

    utils::log("[server] forwarding user's %s pubkeys to %s", //
               userNameSrc.c_str(),
               userNameDest.c_str());

    Proto::Frame userKeysframe;
    Proto::populateHeader(userKeysframe, userNameSrc, userNameDest);

    const uint32_t payloadKeysSize = crypto::kPubKeySignatureByteCount + crypto::kPubKeyByteCount;
    utils::ByteArray baKeys{payloadKeysSize};
    uint8_t *payloadKeys = baKeys.data.get();

    memcpy( //
        payloadKeys,
        keysToSendSign.mKeyPub,
        crypto::kPubKeySignatureByteCount);
    memcpy( //
        payloadKeys + crypto::kPubKeySignatureByteCount,
        keysToSendEncrypt.mKeyPub,
        crypto::kPubKeyByteCount);

    // signing & encrypting with server keys?
    auto signedKeys = //
        crypto::sign(mKeyMyAsymSign, payloadKeys, payloadKeysSize);
    auto encryptedKeys =
        crypto::asymEncrypt(userHandleDest->keyEncrypt, signedKeys.data.get(), signedKeys.dataSize);

    Proto::populatePayload( //
        userKeysframe,
        Proto::PayloadType::kUserPubKeys,
        encryptedKeys.data.get(),
        encryptedKeys.dataSize);

    auto serializedUserKeysFrame = Proto::serialize(userKeysframe);

    const bool sendOk = mTransport.sendBlocking( //
        serializedUserKeysFrame.get(),
        userKeysframe.getSize(),
        userHandleDestFound->mSession);
    assert(sendOk);
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
