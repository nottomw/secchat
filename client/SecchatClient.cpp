#include "SecchatClient.hpp"

#include "UserInterface.hpp"
#include "Utils.hpp"

#include <chrono>
#include <iostream>
#include <thread>

SecchatClient::SecchatClient(std::vector<std::string> &messageUIScrollback)
    : mTransport{}
    , mReaderShouldRun{true}
    , mSymmetricEncryptionReady{false}
    , mMessageUIScrollback{messageUIScrollback}
{
    if (!crypto::init())
    {
        ui::print("Crypto init failed\n");
        assert(false); // fatal error...
    }

    ui::print("[client] -- crypto keys begin --\n");
    ui::print("[client] crypto: generatic signing key pair, pub:\n");
    mKeyMyAsymSign = crypto::keygenAsymSign();
    ui::printCharactersHex(mKeyMyAsymSign.mKeyPub, crypto::kPubKeySignatureByteCount);

    ui::print("[client] crypto: generatic encrypting key pair, pub:\n");
    mKeyMyAsym = crypto::keygenAsym();
    ui::printCharactersHex(mKeyMyAsym.mKeyPub, crypto::kPubKeyByteCount);

    ui::print("[client] -- crypto keys end --\n");
}

void SecchatClient::connectToServer(const std::string &ipAddr, const uint16_t port)
{
    mTransport.onDisconnect( //
        [](std::weak_ptr<Session> /*sess*/) {
            // For client there should be only a single session (to server),
            // this means we got disconnected and have to handle this...
            ui::print("[client] disconnected from server, closing client...\n");
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
    ui::print("[client] joining room %s\n", roomName.c_str());

    serverJoinRoom(roomName);

    std::string roomNameCopy = roomName;
    auto fut = mWaitQueue.waitFor(utils::WaitEventType::kUserJoined, std::move(roomNameCopy));
    auto status = fut.wait_for(std::chrono::seconds(2));
    if (status != std::future_status::ready)
    {
        return false;
    }

    ui::print("[client] joined room %s\n", roomName.c_str());

    return true;
}

bool SecchatClient::sendMessage(const std::string &roomName, const std::string &message)
{
    if (mSymmetricEncryptionReady == false)
    {
        ui::print("[client] symmetric encryption not established yet, dropping message %s\n", message.c_str());
        return false;
    }

    Proto::Frame frame;

    Proto::populateHeader(frame, mMyUserName, roomName);

    // TODO: in this case should the data really be signed? This requires
    // for all users to know pub key of each other user in room.

    const uint32_t messageSize = message.size() - 1; // -1 for '\0'
    crypto::SignedData signedData =                  //
        crypto::sign(                                //
            mKeyMyAsymSign,
            (uint8_t *)message.c_str(),
            messageSize);

    crypto::EncryptedData encryptedData = //
        crypto::symEncrypt(mKeyChatGroup, //
                           signedData.data.get(),
                           signedData.dataSize);

    Proto::populatePayload( //
        frame,
        Proto::PayloadType::k$$$MessageToRoom,
        encryptedData.data.get(),
        encryptedData.dataSize);

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

            default:
                ui::print("[server] received incorrect frame, drop: [");
                ui::printCharactersHex(data, dataLen, '\0');
                ui::print("]\n");
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

    ui::print("[client] received server pubsign/pub keys\n");
    ui::print("[client] server sign pubkey:\n");
    ui::printCharactersHex(connAck.pubSignKey, crypto::kPubKeySignatureByteCount);

    ui::print("[client] server encrypt pubkey:\n");
    ui::printCharactersHex(connAck.pubEncryptKey, crypto::kPubKeyByteCount);

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
        ui::print("[client] signature verification failed, source: %s\n", source.c_str());
        return;
    }

    Proto::PayloadJoinReqAck reqAck = //
        Proto::deserializeJoinReqAck(nonsignedData->data.get(), nonsignedData->dataSize);

    mJoinedRooms.push_back(reqAck.roomName);

    if (reqAck.newRoom)
    {
        newSymKeyRequested(source, reqAck.roomName);
    }

    mWaitQueue.complete(utils::WaitEventType::kUserJoined, reqAck.roomName);
}

void SecchatClient::newSymKeyRequested( //
    const std::string &source,
    const std::string &roomName)
{
    ui::print("[client] %s requested new symmetric key generation for room %s\n", //
              source.c_str(),
              roomName.c_str());

    mKeyChatGroup = crypto::keygenSym();

    mSymmetricEncryptionReady = true;
}

void SecchatClient::handleCurrentSymKeyRequest(Proto::Frame &frame)
{
    //    Proto::Frame symKeyFrame;
    //    Proto::populateHeader(symKeyFrame, mMyUserName, roomName);
    //    Proto::populatePayloadChatGroupSymKeyResponse( //
    //        symKeyFrame,
    //        mKeyChatGroup,
    //        mKeyMyAsymSign,
    //        mKeyMyAsym);

    //    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    //    assert(buffer);

    //    mTransport.sendBlocking(buffer.get(), frame.getSize());
}

void SecchatClient::handleMessageToRoom(Proto::Frame &frame)
{
    const Proto::Header &header = frame.getHeader();
    const Proto::Payload &payload = frame.getPayload();

    std::string userName;
    std::string roomName;
    std::string message;

    // TODO: the message signature should be verified
    // TODO: the message should be decrypted with sym key

    userName.assign(header.source.get(), header.sourceSize);
    roomName.assign(header.destination.get(), header.destinationSize);
    message.assign((char *)payload.payload.get(), payload.size);

    const std::string formattedMessage = //
        utils::formatChatMessage(roomName, userName, message);

    mMessageUIScrollback.push_back(formattedMessage);
}
