#include "SecchatClient.hpp"

#include "UserInterface.hpp"
#include "Utils.hpp"

#include <chrono>
#include <iostream>
#include <thread>

SecchatClient::SecchatClient()
    : mTransport{}
    , mReaderShouldRun{true}
    , mSymmetricEncryptionReady{false}
{
    if (!crypto::init())
    {
        ui::print("Crypto init failed");
        assert(false); // fatal error...
    }

    mKeyMyAsymSign = crypto::keygenAsymSign();
    mKeyMyAsym = crypto::keygenAsym();

    const std::string keySignPubStrHex = utils::formatCharactersHex(mKeyMyAsymSign.mKeyPub, 5);
    const std::string keyEncrPubStrHex = utils::formatCharactersHex(mKeyMyAsym.mKeyPub, 5);

    ui::print("[client] CLIENTS CRYPTO KEY: sign pub key: [ %s ]", keySignPubStrHex.c_str());
    ui::print("[client] CLIENTS CRYPTO KEY: encr pub key: [ %s ]", keyEncrPubStrHex.c_str());
}

void SecchatClient::connectToServer(const std::string &ipAddr, const uint16_t port)
{
    mTransport.onDisconnect( //
        [](std::weak_ptr<Session> /*sess*/) {
            // For client there should be only a single session (to server),
            // this means we got disconnected and have to handle this...
            ui::print("[client] disconnected from server, closing client...");
            ui::stopUserInterface();

            // The disconnect should probably trigger server connection retry,
            // now it will just print message and exit...
        });

    mTransport.connect(ipAddr, port);

    mChatReader = std::thread{[&]() { //
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

void SecchatClient::disconnectFromServer()
{
    mReaderShouldRun = false;
    mChatReader.join();
}

bool SecchatClient::startChat(const std::string &userName)
{
    mMyUserName = userName;

    userConnect();

    std::string userNameCopy = userName;
    auto fut = mWaitQueue.waitFor( //
        utils::WaitEventType::kUserConnectAck,
        std::move(userNameCopy));

    auto status = fut.wait_for(std::chrono::seconds(2));
    if (status != std::future_status::ready)
    {
        return false;
    }

    return true;
}

bool SecchatClient::joinRoom(const std::string &roomName)
{
    ui::print("[client] joining room %s", roomName.c_str());

    serverJoinRoom(roomName);

    std::string roomNameCopy = roomName;
    auto fut = mWaitQueue.waitFor(utils::WaitEventType::kUserJoined, std::move(roomNameCopy));
    auto status = fut.wait_for(std::chrono::seconds(2));
    if (status != std::future_status::ready)
    {
        return false;
    }

    ui::print("[client] joined room %s", roomName.c_str());

    return true;
}

bool SecchatClient::sendMessage(const std::string &roomName, const std::string &message)
{
    if (mSymmetricEncryptionReady == false)
    {
        ui::print("[client] symmetric encryption not established yet, dropping message %s",
                  message.c_str());
        return false;
    }

    Proto::Frame frame;
    Proto::populateHeader(frame, mMyUserName, roomName);
    Proto::populatePayloadMessage(frame, message, mKeyMyAsymSign, mKeyChatGroup);

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    assert(buffer);

    const bool sendOk = mTransport.sendBlocking(buffer.get(), frame.getSize());

    return sendOk;
}

void SecchatClient::handlePacket( //
    const uint8_t *const data,
    const uint32_t dataLen,
    std::shared_ptr<Session> /*session*/)
{
    auto receivedFrames = Proto::deserialize(data, dataLen);
    for (auto &framesIt : receivedFrames)
    {
        Proto::Payload &payload = framesIt.getPayload();
        switch (payload.type)
        {
            case Proto::PayloadType::kUserConnectAck:
                handleConnectAck(framesIt);
                break;

            case Proto::PayloadType::kChatRoomJoined:
                handleChatRoomJoined(framesIt);
                break;

            case Proto::PayloadType::k$$$MessageToRoom:
                handleMessageToRoom(framesIt);
                break;

            case Proto::PayloadType::kUserPubKeys:
                handleUserPubKeys(framesIt);
                break;

            case Proto::PayloadType::kChatGroupCurrentSymKeyRequest:
                handleCurrentSymKeyRequest(framesIt);
                break;

            case Proto::PayloadType::kChatGroupCurrentSymKeyResponse:
                handleCurrentSymKeyResponse(framesIt);
                break;

            case Proto::PayloadType::kNewSymKeyRequest:
                handleNewSymKeyRequest(framesIt);
                break;

            default:
                {
                    const std::string invalidFrameStrHex = //
                        utils::formatCharactersHex(data, dataLen);
                    Proto::Header &header = framesIt.getHeader();
                    const std::string source{header.source.get(), header.sourceSize};
                    ui::print("[client] received incorrect frame from %s - drop, type: %d [ %s ]",
                              source.c_str(),
                              payload.type,
                              invalidFrameStrHex.c_str());
                }
                break;
        }
    }
}

void SecchatClient::userConnect()
{
    const std::string dest{"server"};

    Proto::Frame frame;
    Proto::populateHeader(frame, mMyUserName, dest);
    Proto::populatePayloadUserConnect(frame, mMyUserName, mKeyMyAsymSign, mKeyMyAsym);

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    assert(buffer);

    mTransport.sendBlocking(buffer.get(), frame.getSize());
}

void SecchatClient::handleConnectAck(Proto::Frame &frame)
{
    Proto::Payload &pay = frame.getPayload();
    const uint8_t *const payloadPtr = pay.payload.get();
    const uint32_t payloadSize = pay.size;

    const crypto::DecryptedData data = crypto::asymDecrypt(mKeyMyAsym, payloadPtr, payloadSize);

    Proto::PayloadUserConnectAck connAck = //
        Proto::deserializeUserConnectAck(data.data.get(), data.dataSize);

    const std::string signKeyHex = utils::formatCharactersHex(connAck.pubSignKey, 5);
    const std::string encryptKeyHex = utils::formatCharactersHex(connAck.pubEncryptKey, 5);
    ui::print("[client] received server pubsign [ %s ] and pub encrypt [ %s ] keys", //
              signKeyHex.c_str(),
              encryptKeyHex.c_str());

    memcpy(mKeyServerAsymSign.mKeyPub, connAck.pubSignKey, crypto::kPubKeySignatureByteCount);
    memcpy(mKeyServerAsym.mKeyPub, connAck.pubEncryptKey, crypto::kPubKeyByteCount);

    Proto::Header &header = frame.getHeader();
    const std::string ackedUser{header.destination.get(), header.destinationSize};

    mWaitQueue.complete(utils::WaitEventType::kUserConnectAck, ackedUser);
}

void SecchatClient::serverJoinRoom(const std::string &roomName)
{
    Proto::Frame frame;

    Proto::populateHeader(frame, mMyUserName, "server");

    Proto::populatePayloadChatRoomJoinOrAck( //
        frame,
        roomName,
        mKeyMyAsymSign,
        mKeyServerAsym);

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    assert(buffer);

    mTransport.sendBlocking(buffer.get(), frame.getSize());
}

void SecchatClient::handleChatRoomJoined(Proto::Frame &frame)
{
    Proto::Header &header = frame.getHeader();
    Proto::Payload &payload = frame.getPayload();

    const std::string source{(char *)header.source.get(), header.sourceSize};

    auto decrypted = crypto::asymDecrypt( //
        mKeyMyAsym,
        payload.payload.get(),
        payload.size);
    // TODO: there should be a option to check if decryption OK

    auto nonsignedData = crypto::signedVerify( //
        mKeyServerAsymSign,
        decrypted.data.get(),
        decrypted.dataSize);
    if (!nonsignedData)
    {
        ui::print("[client] signature verification failed, source: %s", source.c_str());
        return;
    }

    Proto::PayloadJoinReqAck reqAck = //
        Proto::deserializeJoinReqAck(nonsignedData->data.get(), nonsignedData->dataSize);

    mJoinedRooms.push_back(reqAck.roomName);

    if (reqAck.newRoom)
    {
        newSymKeyRequested(source, reqAck.roomName);
    }
    else
    {
        // if the room already existed, the client have to request current sym key
        requestCurrentSymKey(reqAck.roomName);
    }

    mWaitQueue.complete(utils::WaitEventType::kUserJoined, reqAck.roomName);
}

void SecchatClient::newSymKeyRequested( //
    const std::string &source,
    const std::string &roomName)
{
    ui::print("[client] %s requested new symmetric key generation for room %s, generating", //
              source.c_str(),
              roomName.c_str());

    mKeyChatGroup = crypto::keygenSym();

    mSymmetricEncryptionReady = true;
}

void SecchatClient::requestCurrentSymKey(const std::string &roomName)
{
    // Send to server request for current sym group chat key.
    // The server then will forward the request and the users public key to
    // selected chat participants and will return the encrypted sym key to requestor.

    Proto::Frame frame;

    Proto::populateHeader(frame, mMyUserName, "server");

    auto signedPayload = crypto::sign(mKeyMyAsymSign, (uint8_t *)roomName.c_str(), roomName.size());
    auto encryptedPayload =
        crypto::asymEncrypt(mKeyServerAsym, signedPayload.data.get(), signedPayload.dataSize);

    Proto::populatePayload( //
        frame,
        Proto::PayloadType::kChatGroupCurrentSymKeyRequest,
        (uint8_t *)encryptedPayload.data.get(),
        encryptedPayload.dataSize);

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    assert(buffer);

    mTransport.sendBlocking(buffer.get(), frame.getSize());
}

void SecchatClient::handleUserPubKeys(Proto::Frame &frame)
{
    Proto::Header &header = frame.getHeader();
    Proto::Payload &payload = frame.getPayload();

    const std::string source{(char *)header.source.get(), header.sourceSize};

    auto decrypted =         //
        crypto::asymDecrypt( //
            mKeyMyAsym,
            payload.payload.get(),
            payload.size);
    auto unsignedPayloadOpt = //
        crypto::signedVerify( //
            mKeyServerAsymSign,
            decrypted.data.get(),
            decrypted.dataSize);
    if (!unsignedPayloadOpt)
    {
        ui::print("[client] failed to verify signature of server (%s), abort");
        return;
    }

    const uint8_t *const keysPlain = unsignedPayloadOpt->data.get();

    RemoteUserKeys remoteUserKeys;
    memcpy(remoteUserKeys.mSign.mKeyPub,
           keysPlain, //
           crypto::kPubKeySignatureByteCount);
    memcpy(remoteUserKeys.mEncrypt.mKeyPub, //
           keysPlain + crypto::kPubKeySignatureByteCount,
           crypto::kPubKeyByteCount);

    ui::print("[client] received asym keys from user %s", //
              source.c_str());

    mRemoteUserKeys[source] = std::move(remoteUserKeys);
}

void SecchatClient::handleCurrentSymKeyRequest(Proto::Frame &frame)
{
    Proto::Header &header = frame.getHeader();
    Proto::Payload &payload = frame.getPayload();

    const std::string source{(char *)header.source.get(), header.sourceSize};

    if (mRemoteUserKeys.count(source) == 0)
    {
        ui::print("[client] keys for user %s missing, drop", source.c_str());
        return;
    }

    auto remoteUserKeys = mRemoteUserKeys[source];

    auto decrypted = crypto::asymDecrypt(mKeyMyAsym, payload.payload.get(), payload.size);

    auto nonsigned =
        crypto::signedVerify(mKeyServerAsymSign, decrypted.data.get(), decrypted.dataSize);
    if (!nonsigned)
    {
        ui::print("[client] failed to verify server's signature, drop");
        return;
    }

    Proto::PayloadRequestCurrentSymKey req =
        Proto::deserializeRequestCurrentSymKey(nonsigned->data.get(), nonsigned->dataSize);

    ui::print("[client] received sym key request from user %s for room %s", //
              source.c_str(),
              req.roomName.c_str());

    Proto::Frame symKeyReply;
    Proto::populateHeader(symKeyReply, mMyUserName, source);

    // encrypt with requesting user asym key

    const auto asymKeyHex = utils::formatCharactersHex(mKeyChatGroup.mKey, 5);
    ui::print("[client] ##### SENDING SYM KEY [ %s ] #####", asymKeyHex.c_str());

    auto symKeySigned = crypto::sign(mKeyMyAsymSign, mKeyChatGroup.mKey, crypto::kSymKeyByteCount);
    auto symKeyEncrypted = crypto::asymEncrypt( //
        remoteUserKeys.mEncrypt,
        symKeySigned.data.get(),
        symKeySigned.dataSize);

    Proto::populatePayload(symKeyReply,
                           Proto::PayloadType::kChatGroupCurrentSymKeyResponse,
                           symKeyEncrypted.data.get(),
                           symKeyEncrypted.dataSize);

    auto serializedSymKey = Proto::serialize(symKeyReply);

    mTransport.sendBlocking(serializedSymKey.get(), symKeyReply.getSize());
}

void SecchatClient::handleCurrentSymKeyResponse(Proto::Frame &frame)
{
    const Proto::Header &header = frame.getHeader();
    const Proto::Payload &payload = frame.getPayload();

    const std::string source{(char *)header.source.get(), header.sourceSize};

    const uint32_t matchingUsersCount = mRemoteUserKeys.count(source);
    if (matchingUsersCount == 0U)
    {
        ui::print("[client] missing keys from user %s, drop", source.c_str());
        return;
    }

    auto remoteUserKeys = mRemoteUserKeys[source];

    auto decrypted = crypto::asymDecrypt(mKeyMyAsym, payload.payload.get(), payload.size);
    auto nonsigned =
        crypto::signedVerify(remoteUserKeys.mSign, decrypted.data.get(), decrypted.dataSize);
    if (!nonsigned)
    {
        ui::print("[client] failed to verify signature from from user %s, drop", source.c_str());
        return;
    }

    memcpy(mKeyChatGroup.mKey, nonsigned->data.get(), nonsigned->dataSize);
    const auto symKeyHex = utils::formatCharactersHex(mKeyChatGroup.mKey, 5);
    ui::print("[client] ##### RECEIVED SYM KEY [ %s ] from user %s #####",
              symKeyHex.c_str(),
              source.c_str());

    mSymmetricEncryptionReady = true; // we now have full encryption
}

void SecchatClient::handleMessageToRoom(Proto::Frame &frame)
{
    const Proto::Header &header = frame.getHeader();
    const Proto::Payload &payload = frame.getPayload();

    std::string userName;
    std::string roomName;

    userName.assign(header.source.get(), header.sourceSize);
    roomName.assign(header.destination.get(), header.destinationSize);

    if (mSymmetricEncryptionReady == false)
    {
        const auto msg = utils::formatCharacters(payload.payload.get(), payload.size);
        ui::print("[client] received message from %s but encryption not ready yet: %s", //
                  userName.c_str(),                                                     //
                  msg.c_str());
        return;
    }

    Proto::PayloadMessage payMsg = //
        Proto::deserializeMessage(payload.payload.get(), payload.size);

    auto decrypted = crypto::symDecrypt( //
        mKeyChatGroup,
        payMsg.msg.data.get(),
        payMsg.msg.dataSize,
        payMsg.nonce);
    if (!decrypted)
    {
        ui::print("[client] message decrypt failed with sym key");
        return;
    }

    if (mRemoteUserKeys.count(userName) == 0)
    {
        ui::print("[client] received message from user %s, but cannot verify signature (no "
                  "keys), drop",
                  userName.c_str());
        return;
    }

    auto remoteUserKeys = mRemoteUserKeys[userName];

    auto nonsigned = crypto::signedVerify( //
        remoteUserKeys.mSign,
        decrypted->data.get(),
        decrypted->dataSize);
    if (!nonsigned)
    {
        ui::print("[client] user %s signature verification failed, drop", userName.c_str());
        return;
    }

    std::string message{(char *)nonsigned->data.get(), nonsigned->dataSize};

    const std::string formattedMessage = //
        utils::formatChatMessage(roomName, userName, message);

    ui::print(formattedMessage.c_str());
}

void SecchatClient::handleNewSymKeyRequest(Proto::Frame &frame)
{
    const Proto::Header &header = frame.getHeader();
    const Proto::Payload &payload = frame.getPayload();

    const std::string source{header.source.get(), header.sourceSize};

    auto decrypted = crypto::asymDecrypt( //
        mKeyMyAsym,
        payload.payload.get(),
        payload.size);

    auto nonsignedData = crypto::signedVerify( //
        mKeyServerAsymSign,
        decrypted.data.get(),
        decrypted.dataSize);
    if (!nonsignedData)
    {
        ui::print("[client] signature verification failed, source: %s", source.c_str());
        return;
    }

    auto payNewKey =
        Proto::deserializeRequestCurrentSymKey(nonsignedData->data.get(), nonsignedData->dataSize);

    newSymKeyRequested(source, payNewKey.roomName);
}
