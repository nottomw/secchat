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

bool SecchatClient::sendMessage( //
    const std::string &roomName,
    const std::string &message)
{
    if (mSymmetricEncryptionReady == false)
    {
        ui::print("[client] symmetric encryption not established yet, dropping message %s",
                  message.c_str());
        return false;
    }

    auto nonceBa = crypto::symEncryptGetNonce();

    crypto::SignedData signedData = //
        crypto::sign(               //
            mKeyMyAsymSign,
            (uint8_t *)message.c_str(),
            message.size());

    crypto::EncryptedData encryptedData = //
        crypto::symEncrypt(mKeyChatGroup, //
                           signedData.data.get(),
                           signedData.dataSize,
                           nonceBa);

    proto::PayloadMessage pay;
    pay.set_nonce(nonceBa.ptr(), nonceBa.size());
    pay.set_msg(encryptedData.data.get(), encryptedData.dataSize);

    const auto serializedPay = proto::serializePayload(pay);

    proto::Frame frame;
    frame.set_source(mMyUserName);
    frame.set_destination(roomName);
    frame.set_payloadtype(proto::PayloadType::kMessageToRoom);
    frame.set_payload(serializedPay.ptr(), serializedPay.size());

    const auto serializedFrame = serializeFrame(frame);

    const bool sendOk = mTransport.sendBlocking(serializedFrame.ptr(), serializedFrame.size());

    return sendOk;
}

void SecchatClient::handlePacket( //
    const uint8_t *const data,
    const uint32_t dataLen,
    std::shared_ptr<Session> /*session*/)
{
    // TODO: !!!!! can receive multiple frames in single packed?
    auto receivedFrame = proto::deserializeFrame(data, dataLen);
    //    for (auto &framesIt : receivedFrames)
    //    {
    switch (receivedFrame.payloadtype())
    {
        case proto::PayloadType::kUserConnectAck:
            handleConnectAck(receivedFrame);
            break;

        case proto::PayloadType::kChatRoomJoined:
            handleChatRoomJoined(receivedFrame);
            break;

        case proto::PayloadType::kMessageToRoom:
            handleMessageToRoom(receivedFrame);
            break;

        case proto::PayloadType::kUserPubKeys:
            handleUserPubKeys(receivedFrame);
            break;

        case proto::PayloadType::kChatGroupCurrentSymKeyRequest:
            handleCurrentSymKeyRequest(receivedFrame);
            break;

        case proto::PayloadType::kChatGroupCurrentSymKeyResponse:
            handleCurrentSymKeyResponse(receivedFrame);
            break;

        case proto::PayloadType::kNewSymKeyRequest:
            handleNewSymKeyRequest(receivedFrame);
            break;

        default:
            {
                const std::string invalidFrameStrHex = //
                    utils::formatCharactersHex(data, dataLen);
                ui::print("[client] received incorrect frame from %s - drop, type: %d [ %s ]",
                          receivedFrame.source().c_str(),
                          receivedFrame.payloadtype(),
                          invalidFrameStrHex.c_str());
            }
            break;
    }
    //    }
}

void SecchatClient::userConnect()
{
    proto::PayloadUserConnectOrAck pay;
    pay.set_username(mMyUserName);
    pay.set_pubsignkey(mKeyMyAsymSign.mKeyPub, crypto::kPubKeySignatureByteCount);
    pay.set_pubencryptkey(mKeyMyAsym.mKeyPub, crypto::kPubKeyByteCount);

    const auto serializedPay = proto::serializePayload(pay);

    proto::Frame frame;
    frame.set_source(mMyUserName);
    frame.set_destination("server");
    frame.set_payloadtype(proto::PayloadType::kUserConnect);
    frame.set_payload(serializedPay.ptr(), serializedPay.size());

    const auto serializedFrame = serializeFrame(frame);

    mTransport.sendBlocking(serializedFrame.ptr(), serializedFrame.size());
}

void SecchatClient::handleConnectAck(proto::Frame &frame)
{
    auto payBuf = frame.payload();

    // TODO: handle isAck

    const crypto::DecryptedData payData =
        crypto::asymDecrypt(mKeyMyAsym, (uint8_t *)payBuf.data(), payBuf.size());

    proto::PayloadUserConnectOrAck pay =                           //
        proto::deserializePayload<proto::PayloadUserConnectOrAck>( //
            payData.data.get(),
            payData.dataSize);

    const std::string signKeyHex =
        utils::formatCharactersHex((uint8_t *)pay.pubsignkey().data(), 5);
    const std::string encryptKeyHex =
        utils::formatCharactersHex((uint8_t *)pay.pubencryptkey().data(), 5);
    ui::print("[client] received server pubsign [ %s ] and pub encrypt [ %s ] keys", //
              signKeyHex.c_str(),
              encryptKeyHex.c_str());

    memcpy(mKeyServerAsymSign.mKeyPub, pay.pubsignkey().data(), crypto::kPubKeySignatureByteCount);
    memcpy(mKeyServerAsym.mKeyPub, pay.pubencryptkey().data(), crypto::kPubKeyByteCount);

    const std::string ackedUser{frame.source()};
    mWaitQueue.complete(utils::WaitEventType::kUserConnectAck, std::move(ackedUser));
}

void SecchatClient::serverJoinRoom(const std::string &roomName)
{
    proto::PayloadJoinRequestOrAck pay;
    pay.set_roomname(roomName);

    auto paySerialized = proto::serializePayload(pay);
    auto encrypted = crypto::signAndEncrypt(paySerialized, mKeyMyAsymSign, mKeyServerAsym);

    proto::Frame frame;
    frame.set_source(mMyUserName);
    frame.set_destination("server");
    frame.set_payloadtype(proto::PayloadType::kMessageToRoom);
    frame.set_payload(encrypted.data.get(), encrypted.dataSize);

    auto buffer = proto::serializeFrame(frame);

    mTransport.sendBlocking(buffer.ptr(), buffer.size());
}

void SecchatClient::handleChatRoomJoined(proto::Frame &frame)
{
    auto pay = frame.payload();

    auto nonsignedData = crypto::decryptAndSignVerify(
        (uint8_t *)pay.data(), pay.size(), mKeyServerAsymSign, mKeyMyAsym);
    if (!nonsignedData)
    {
        ui::print("[client] signature verification failed, source: %s", frame.source().c_str());
        return;
    }

    proto::PayloadJoinRequestOrAck reqAck = //
        proto::deserializePayload<proto::PayloadJoinRequestOrAck>(nonsignedData->data.get(),
                                                                  nonsignedData->dataSize);

    mJoinedRooms.push_back(reqAck.roomname());

    assert(reqAck.has_newroom());

    if (reqAck.newroom() == true)
    {
        newSymKeyRequested(frame.source(), reqAck.roomname());
    }
    else
    {
        // if the room already existed, the client have to request current sym key
        requestCurrentSymKey(reqAck.roomname());
    }

    std::string roomNameCpy{reqAck.roomname()};
    mWaitQueue.complete(utils::WaitEventType::kUserJoined, std::move(roomNameCpy));
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

    proto::PayloadChatGroupCurrentSymKeyRequestOrResponse pay;
    pay.set_roomname(roomName);

    auto paySerialized = proto::serializePayload(pay);
    auto encrypted = crypto::signAndEncrypt(paySerialized, mKeyMyAsymSign, mKeyServerAsym);

    proto::Frame frame;
    frame.set_source(mMyUserName);
    frame.set_destination("server");
    frame.set_payloadtype(proto::PayloadType::kChatGroupCurrentSymKeyRequest);
    frame.set_payload(encrypted.data.get(), encrypted.dataSize);

    auto ser = proto::serializeFrame(frame);

    mTransport.sendBlocking(ser.ptr(), ser.size());
}

void SecchatClient::handleUserPubKeys(proto::Frame &frame)
{
    auto source = frame.source();

    auto pay = frame.payload();
    auto decryptedPayOpt = crypto::decryptAndSignVerify(
        (uint8_t *)pay.data(), pay.size(), mKeyServerAsymSign, mKeyMyAsym);
    if (!decryptedPayOpt)
    {
        ui::print("[client] failed to verify signature of server (%s), abort", source.c_str());
        return;
    }

    const uint8_t *const keysPlain = decryptedPayOpt->data.get();

    RemoteUserKeys remoteUserKeys;
    memcpy(remoteUserKeys.mSign.mKeyPub,
           keysPlain, //
           crypto::kPubKeySignatureByteCount);
    memcpy(remoteUserKeys.mEncrypt.mKeyPub, //
           keysPlain + crypto::kPubKeySignatureByteCount,
           crypto::kPubKeyByteCount);

    ui::print("[client] received asym keys from user %s", source.c_str());

    mRemoteUserKeys[source] = std::move(remoteUserKeys);
}

void SecchatClient::handleCurrentSymKeyRequest(proto::Frame &frame)
{
    auto source = frame.source();
    if (mRemoteUserKeys.count(source) == 0)
    {
        ui::print("[client] keys for user %s missing, drop", source.c_str());
        return;
    }

    auto remoteUserKeys = mRemoteUserKeys[source];

    auto pay = frame.payload();

    auto nonsigned = crypto::decryptAndSignVerify(
        (uint8_t *)pay.data(), pay.size(), mKeyServerAsymSign, mKeyMyAsym);
    if (!nonsigned)
    {
        ui::print("[client] failed to verify server's signature, drop");
        return;
    }

    proto::PayloadChatGroupCurrentSymKeyRequestOrResponse req =
        proto::deserializePayload<proto::PayloadChatGroupCurrentSymKeyRequestOrResponse>(
            nonsigned->data.get(), nonsigned->dataSize);

    ui::print("[client] received sym key request from user %s for room %s", //
              source.c_str(),
              req.roomname().c_str());

    {
        // reply with the asym key
        // here would be a good place to ask the user if he wants to provide the key

        const auto asymKeyHex = utils::formatCharactersHex(mKeyChatGroup.mKey, 5);
        ui::print("[client] ##### SENDING SYM KEY [ %s ] #####", asymKeyHex.c_str());

        // encrypt with requesting user asym key
        auto symKeyEncrypted = crypto::signAndEncrypt(
            mKeyChatGroup.mKey, crypto::kSymKeyByteCount, mKeyMyAsymSign, remoteUserKeys.mEncrypt);

        proto::PayloadChatGroupCurrentSymKeyRequestOrResponse payResp;
        payResp.set_roomname(req.roomname());
        payResp.set_key(symKeyEncrypted.data.get(), symKeyEncrypted.dataSize);

        auto paySerialized = proto::serializePayload(payResp);

        proto::Frame symKeyReply;
        symKeyReply.set_source(mMyUserName);
        symKeyReply.set_destination(source);
        symKeyReply.set_payloadtype(proto::PayloadType::kChatGroupCurrentSymKeyResponse);
        symKeyReply.set_payload(paySerialized.ptr(), paySerialized.size());

        auto replySer = proto::serializeFrame(symKeyReply);

        mTransport.sendBlocking(replySer.ptr(), replySer.size());
    }
}

void SecchatClient::handleCurrentSymKeyResponse(proto::Frame &frame)
{
    auto source = frame.source();
    const uint32_t matchingUsersCount = mRemoteUserKeys.count(source);
    if (matchingUsersCount == 0U)
    {
        ui::print("[client] missing keys from user %s, drop", source.c_str());
        return;
    }

    auto remoteUserKeys = mRemoteUserKeys[source];

    auto nonsigned = crypto::decryptAndSignVerify((uint8_t *)frame.payload().data(),
                                                  frame.payload().size(),
                                                  remoteUserKeys.mSign,
                                                  mKeyMyAsym);
    if (!nonsigned)
    {
        ui::print("[client] failed to verify signature from from user %s, drop", source.c_str());
        return;
    }

    proto::PayloadChatGroupCurrentSymKeyRequestOrResponse resp =
        proto::deserializePayload<proto::PayloadChatGroupCurrentSymKeyRequestOrResponse>(
            nonsigned->data.get(), nonsigned->dataSize);

    if (resp.has_key() == false)
    {
        ui::print("[client] no key in payload, drop");
        return;
    }

    memcpy(mKeyChatGroup.mKey, resp.key().data(), resp.key().size());

    const auto symKeyHex = utils::formatCharactersHex(mKeyChatGroup.mKey, 5);
    ui::print("[client] ##### RECEIVED SYM KEY [ %s ] from user %s room %s #####",
              symKeyHex.c_str(),
              source.c_str(),
              resp.roomname().c_str());

    mSymmetricEncryptionReady = true; // we now have full encryption
}

void SecchatClient::handleMessageToRoom(proto::Frame &frame)
{
    std::string userName{frame.source()};
    std::string roomName{frame.destination()};

    if (mSymmetricEncryptionReady == false)
    {
        const auto msg =
            utils::formatCharacters((uint8_t *)frame.payload().data(), frame.payload().size());
        ui::print("[client] received message from %s but encryption not ready yet, drop", //
                  userName.c_str(),                                                       //
                  msg.c_str());
        return;
    }

    auto pay = frame.payload();

    proto::PayloadMessage payMsg = //
        proto::deserializePayload<proto::PayloadMessage>((uint8_t *)pay.data(), pay.size());

    utils::ByteArray nonce{(uint8_t *)payMsg.nonce().data(), (uint32_t)payMsg.nonce().size()};

    auto decrypted = crypto::symDecrypt( //
        mKeyChatGroup,
        (uint8_t *)payMsg.msg().data(),
        payMsg.msg().size(),
        nonce);
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

void SecchatClient::handleNewSymKeyRequest(proto::Frame &frame)
{
    auto source = frame.source();
    auto pay = frame.payload();

    auto nonsignedData = crypto::decryptAndSignVerify(
        (uint8_t *)pay.data(), pay.size(), mKeyServerAsymSign, mKeyMyAsym);
    if (!nonsignedData)
    {
        ui::print("[client] signature verification failed, source: %s", source.c_str());
        return;
    }

    proto::PayloadNewSymKeyRequest payNewKey =
        proto::deserializePayload<proto::PayloadNewSymKeyRequest>(nonsignedData->data.get(),
                                                                  nonsignedData->dataSize);

    newSymKeyRequested(source, payNewKey.roomname());
}
