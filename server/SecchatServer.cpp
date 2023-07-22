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
    uint32_t bytesLeft = dataLen;

    auto receivedFrame = proto::deserializeFrame(dataOffset, bytesLeft);
    while (bytesLeft > 0)
    {
        switch (receivedFrame.payloadtype())
        {
            case proto::PayloadType::kUserConnect:
                handleNewUser(receivedFrame, session);
                break;

            case proto::PayloadType::kChatRoomJoin:
                handleJoinChatRoom(receivedFrame, session);
                break;

            case proto::PayloadType::kMessageToRoom:
                handleMessageToChatRoom(receivedFrame, session, dataOffset);
                break;

            case proto::PayloadType::kChatGroupCurrentSymKeyRequest:
                handleChatGroupSymKeyRequest(receivedFrame);
                break;

            case proto::PayloadType::kChatGroupCurrentSymKeyResponse:
                handleChatGroupSymKeyResponse(receivedFrame, dataOffset);
                break;

            default:
                {
                    const std::string invalidFrameStrHex = //
                        utils::formatCharactersHex(data, dataLen);
                    utils::log("[server] received incorrect frame from %s - drop, type: %d [ %s ]",
                               receivedFrame.source().c_str(),
                               receivedFrame.payloadtype(),
                               invalidFrameStrHex.c_str());
                }
                break;
        }

        bytesLeft -= receivedFrame.ByteSizeLong();
        dataOffset += receivedFrame.ByteSizeLong();
    }
}

void SecchatServer::handleNewUser( //
    proto::Frame &frame,
    std::shared_ptr<Session> session)
{
    auto &pay = frame.payload();

    proto::PayloadUserConnectOrAck newUserFrame =
        proto::deserializePayload<proto::PayloadUserConnectOrAck>(pay.data(), pay.size());

    const std::string newUserName = newUserFrame.username();

    const std::string signKeyHex =
        utils::formatCharactersHex((uint8_t *)newUserFrame.pubsignkey().data(), 5);
    const std::string encryptKeyHex =
        utils::formatCharactersHex((uint8_t *)newUserFrame.pubencryptkey().data(), 5);

    utils::log("[server] received user %s pubsign [ %s ] and pub encrypt [ %s ] keys", //
               newUserName.c_str(),
               signKeyHex.c_str(),
               encryptKeyHex.c_str());

    crypto::KeyAsym userEncryptionPubKey;

    const auto existingUser = verifyUserExists(newUserName);
    if (existingUser)
    {
        // TODO: If this is a existing user, verify the pubsign/pub keys match!!!
        // TODO: if this is a existing user, and pubkeys OK, reply with connect ack, otherwise drop

        // for now just overwriting the session
        User *const user = *existingUser;
        user->mSession = session;

        userEncryptionPubKey = user->keyEncrypt;

        utils::log("[server] user %s already exists (for now update the session)",
                   newUserName.c_str());
    }
    else
    {
        User user;
        user.mUserName = newUserName;
        user.mSession = session;

        memcpy( //
            user.keySign.mKeyPub,
            newUserFrame.pubsignkey().data(),
            crypto::kPubKeySignatureByteCount);
        memcpy( //
            user.keyEncrypt.mKeyPub,
            newUserFrame.pubencryptkey().data(),
            crypto::kPubKeyByteCount);

        userEncryptionPubKey = user.keyEncrypt;

        uint32_t usersCount = 0U;

        mUsers.push_back(std::move(user));
        usersCount = mUsers.size();

        utils::log("[server] new user created: %s, pubsign/pub keys received", newUserName.c_str());
        utils::log("[server] currently %d users active", usersCount);
    }

    {
        // reply with server's pubsign/pub keys (encrypted with users's pub key)

        std::string source{"server"};
        std::string destination = newUserName;

        proto::PayloadUserConnectOrAck payReply;
        payReply.set_username(newUserName);
        payReply.set_pubsignkey(mKeyMyAsymSign.mKeyPub, crypto::kPubKeySignatureByteCount);
        payReply.set_pubencryptkey(mKeyMyAsym.mKeyPub, crypto::kPubKeyByteCount);
        payReply.set_isack(true);

        auto payReplySer = proto::serializePayload(payReply);

        auto payReplyEncrypted =
            crypto::asymEncrypt(userEncryptionPubKey, payReplySer.ptr(), payReplySer.size());

        proto::Frame replyFrame;
        replyFrame.set_source("server");
        replyFrame.set_destination(newUserName);
        replyFrame.set_payloadtype(proto::PayloadType::kUserConnectAck);
        replyFrame.set_payload(payReplyEncrypted.data.get(), payReplyEncrypted.dataSize);

        auto replyFrameSer = proto::serializeFrame(replyFrame);

        const bool sendOk =          //
            mTransport.sendBlocking( //
                replyFrameSer.ptr(),
                replyFrameSer.size(),
                session);
        if (sendOk == false)
        {
            utils::log("[server] FAILED to ACK connect from user %s", destination.c_str());
        }
    }
}

void SecchatServer::handleJoinChatRoom( //
    proto::Frame &frame,
    std::shared_ptr<Session> session)
{
    auto &userName = frame.source();

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

    auto &pay = frame.payload();
    auto nonsignedDataOpt =           //
        crypto::decryptAndSignVerify( //
            pay.data(),
            pay.size(),
            userHandle->keySign,
            mKeyMyAsym);
    if (!nonsignedDataOpt)
    {
        utils::log("[server] signature verification failed, source: %s", userName.c_str());
        return;
    }

    crypto::NonsignedData &nonsignedData = *nonsignedDataOpt;

    proto::PayloadJoinRequestOrAck join = //
        proto::deserializePayload<proto::PayloadJoinRequestOrAck>(nonsignedData.data.get(),
                                                                  nonsignedData.dataSize);

    const std::string roomName = join.roomname();
    utils::log("[server] chatroom join requested from user %s, room name: %s", //
               userName.c_str(),
               roomName.c_str());

    // TODO: quarantine: on join user should be "quarantined" for a couple of
    // seconds, so the other users won't message anything to unknown user

    bool newRoomCreated = false;
    const bool joined = joinUserToRoom(*userHandle, roomName, newRoomCreated);
    if (joined)
    {
        // if new room creation - request sym key generate too
        if (newRoomCreated)
        {
            utils::log("[server] new room created, requesting sym key generation from user %s", //
                       userName.c_str());
        }

        proto::PayloadJoinRequestOrAck joinAck;
        joinAck.set_roomname(roomName);
        joinAck.set_newroom(newRoomCreated);

        auto joinAckSer = proto::serializePayload(joinAck);

        auto joinAckEncrypted = crypto::signAndEncrypt(
            joinAckSer.data.get(), joinAckSer.dataSize, mKeyMyAsymSign, userHandle->keyEncrypt);

        proto::Frame frameAck;
        frameAck.set_source("server");
        frameAck.set_destination(userName);
        frameAck.set_payloadtype(proto::PayloadType::kChatRoomJoined);
        frameAck.set_payload(joinAckEncrypted.data.get(), joinAckEncrypted.dataSize);

        auto frameAckSer = proto::serializeFrame(frameAck);

        const bool sendOk = mTransport.sendBlocking(frameAckSer.ptr(), frameAckSer.size(), session);
        if (sendOk == false)
        {
            utils::log("[server] failed to ack join for user %s room %s",
                       userName.c_str(),
                       roomName.c_str());
            return;
        }

        if (newRoomCreated == false)
        {
            // user just joined new room, send out his keys to all and all keys to him
            userJoinedPubKeysExchange(*userHandle, roomName);
        }
    }
}

void SecchatServer::handleMessageToChatRoom( //
    proto::Frame &frame,
    std::shared_ptr<Session> session,
    const uint8_t *const rawBuffer)
{
    std::string userName = frame.source();
    std::string roomName = frame.destination();

    const auto msgStr = utils::formatCharacters(frame.payload().data(), frame.payload().size());
    utils::log("[server] RX MSG: [%s]<%s>: %s", //
               roomName.c_str(),
               userName.c_str(),
               msgStr.c_str());

    auto roomOpt = findRoomByName(roomName);
    assert(roomOpt);

    Room *const foundRoom = *roomOpt;

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

        const bool sendOk =
            mTransport.sendBlocking(rawBuffer, frame.ByteSizeLong(), userInRoomSession);
        if (sendOk == false)
        {
            utils::log("[server] failed to send message to user %s", user.mUserName.c_str());
            continue;
        }
    }
}

void SecchatServer::handleChatGroupSymKeyRequest( //
    proto::Frame &frame)
{
    const std::string source{frame.source()};
    utils::log("[server] received sym key request from %s", source.c_str());

    auto userOk = verifyUserExists(source);
    if (!userOk)
    {
        utils::log("[server] user %s does not exist, drop", source.c_str());
        return;
    }

    User *userHandleSource = *userOk;

    auto &pay = frame.payload();

    auto unsignedPay = crypto::decryptAndSignVerify(
        pay.data(), pay.length(), userHandleSource->keySign, mKeyMyAsym);
    if (!unsignedPay)
    {
        utils::log("[server] signature verification failed for sym key request, drop");
        return;
    }

    proto::PayloadChatGroupCurrentSymKeyRequestOrResponse payCurrentSymKeyReq = //
        proto::deserializePayload<proto::PayloadChatGroupCurrentSymKeyRequestOrResponse>(
            unsignedPay->data.get(), unsignedPay->dataSize);

    std::string roomName = payCurrentSymKeyReq.roomname();

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

        utils::log("[server] request sym key for room %s from user %s, forwarding to %s", //
                   roomName.c_str(),
                   source.c_str(),
                   joinedUser.mUserName.c_str());

        const bool forwardSuccess = forwardSymKeyRequest(roomName, *userHandleSource, joinedUser);
        if (!forwardSuccess)
        {
            // try again with another user
            continue;
        }

        requestDestinationUserId = &joinedUser; // found one
        break;
    }

    if (requestDestinationUserId == nullptr)
    {
        // looks like just joined user is the only one here,
        // the new sym key generation needs to requested from him
        utils::log("[server] user %s is the only user in this room", source.c_str());
        utils::log("[server] requesting user %s to generate new sym key", source.c_str());
        const bool reqOk = requestNewSymKeyFromUser(roomName, *userHandleSource);
        if (!reqOk)
        {
            utils::log(
                "[server] new sym key generation request failed (sent to user %s), giving up...",
                source.c_str());
        }
    }
}

void SecchatServer::handleChatGroupSymKeyResponse( //
    proto::Frame &frame,
    const uint8_t *const rawBuffer)
{
    const std::string source{frame.source()};
    const std::string dest{frame.destination()};

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

    const bool ok = mTransport.sendBlocking(rawBuffer, frame.ByteSizeLong(), userHandle->mSession);
    if (!ok)
    {
        utils::log("[server] failed to forward sym key from user %s to user %s",
                   source.c_str(),
                   dest.c_str());
        return;
    }
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

                // TODO: this is a hack, should be handled nicer
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
    proto::PayloadNewSymKeyRequest pay;
    pay.set_roomname(roomName);

    auto paySer = proto::serializePayload(pay);

    auto paySerEncrypted = crypto::signAndEncrypt(paySer, mKeyMyAsymSign, userHandle.keyEncrypt);

    proto::Frame frame;
    frame.set_source("server");
    frame.set_destination(roomName);
    frame.set_payloadtype(proto::PayloadType::kNewSymKeyRequest);
    frame.set_payload(paySerEncrypted.data.get(), paySerEncrypted.dataSize);

    auto buffer = proto::serializeFrame(frame);

    const bool sendOk =          //
        mTransport.sendBlocking( //
            buffer.ptr(),
            buffer.size(),
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
            // the already created user should keep hold of his keys and
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
    assert(userHandleDest != nullptr);

    utils::log("[server] forwarding user's %s pubkeys to %s", //
               userNameSrc.c_str(),
               userNameDest.c_str());

    proto::PayloadUserPubKeys payUserPubKeys;
    payUserPubKeys.set_pubsignkey(keysToSendSign.mKeyPub, crypto::kPubKeySignatureByteCount);
    payUserPubKeys.set_pubencryptkey(keysToSendEncrypt.mKeyPub, crypto::kPubKeyByteCount);

    auto payUserPubKeysSer = proto::serializePayload(payUserPubKeys);
    auto payUserPubKeysEncrypted =
        crypto::signAndEncrypt(payUserPubKeysSer, mKeyMyAsymSign, userHandleDest->keyEncrypt);

    proto::Frame userKeysframe;
    userKeysframe.set_source(userNameSrc);
    userKeysframe.set_destination(userNameDest);
    userKeysframe.set_payloadtype(proto::PayloadType::kUserPubKeys);
    userKeysframe.set_payload(payUserPubKeysEncrypted.data.get(), payUserPubKeysEncrypted.dataSize);

    auto serializedUserKeysFrame = proto::serializeFrame(userKeysframe);

    const bool sendOk = mTransport.sendBlocking( //
        serializedUserKeysFrame.ptr(),
        serializedUserKeysFrame.size(),
        userHandleDest->mSession);
    if (sendOk == false)
    {
        utils::log("[server] failed to send pub keys of user %s to %s",
                   userNameSrc.c_str(),
                   userNameDest.c_str());
        return;
    }
}

bool SecchatServer::forwardSymKeyRequest( //
    const std::string &roomName,
    SecchatServer::User &sourceUserHandle,
    SecchatServer::User &destUserHandle)
{
    proto::PayloadChatGroupCurrentSymKeyRequestOrResponse payUserKeys;
    payUserKeys.set_roomname(roomName);

    auto payUserKeysSer = proto::serializePayload(payUserKeys);
    auto payUserKeysEncrypted =
        crypto::signAndEncrypt(payUserKeysSer, mKeyMyAsymSign, destUserHandle.keyEncrypt);

    proto::Frame frameSymKeyRequest;
    frameSymKeyRequest.set_source(sourceUserHandle.mUserName);
    frameSymKeyRequest.set_destination(destUserHandle.mUserName);
    frameSymKeyRequest.set_payloadtype(proto::PayloadType::kChatGroupCurrentSymKeyRequest);
    frameSymKeyRequest.set_payload(payUserKeysEncrypted.data.get(), payUserKeysEncrypted.dataSize);

    auto frameSymKeyRequestSer = proto::serializeFrame(frameSymKeyRequest);

    const bool sendOk =          //
        mTransport.sendBlocking( //
            frameSymKeyRequestSer.ptr(),
            frameSymKeyRequestSer.size(),
            destUserHandle.mSession);
    if (sendOk == false)
    {
        utils::log("[server] sym key request - failed - user disconnected?...");
        return false;
    }

    return true;
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
