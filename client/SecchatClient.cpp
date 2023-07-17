#include "SecchatClient.hpp"

#include "UserInterface.hpp"
#include "Utils.hpp"

#include <chrono>
#include <iostream>
#include <thread>

SecchatClient::SecchatClient(std::vector<std::string> &messageUIScrollback)
    : mTransport{}
    , mReaderShouldRun{true}
    , mMessageUIScrollback{messageUIScrollback}
{
    if (crypto::init())
    {
        ui::print("Crypto init failed\n");
    }

    ui::print("[client] -- crypto keys start --\n");
    ui::print("[client] crypto: generatic signing key pair: pub, priv\n");
    mKeyMyAsym = crypto::keygenAsym();

    ui::printCharactersHex(mKeyMyAsym.mKeyPub, crypto::kPubKeyByteCount);
    ui::printCharactersHex(mKeyMyAsym.mKeyPriv, crypto::kPrivKeyByteCount);

    ui::print("[client] crypto: generatic encrypting key pair\n");
    mKeyMyAsymSign = crypto::keygenAsymSign();

    ui::printCharactersHex(mKeyMyAsymSign.mKeyPub, crypto::kPubKeySignatureByteCount);
    ui::printCharactersHex(mKeyMyAsymSign.mKeyPriv, crypto::kPrivKeySignatureByteCount);

    ui::print("[client] -- crypto keys end --\n");
}

void SecchatClient::connectToServer(const std::string &ipAddr, const uint16_t port)
{
    mTransport.onDisconnect( //
        [](std::weak_ptr<Session> /*sess*/) {
            // For client there should be only a single session (to server),
            // this means we got disconnected and have to handle this...
            ui::print("[client] disconnected from server, closing client...\n");

            // TODO: HACK: pretend we just got ctrl-c'd, otherwise
            // the curses ui is breaking terminal
            ui::handleCtrlC(SIGINT);

            // TODO: the disconnect should probably trigger server connection retry,
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

void SecchatClient::startChat(const std::string &userName)
{
    mMyUserName = userName;

    serverNewUserAnnounce();
}

bool SecchatClient::joinRoom(const std::string &roomName)
{
    ui::print("[client] joining room %s\n", roomName.c_str());

    serverJoinRoom(roomName);

    std::unique_lock lk{mJoinedCondVarMutex};
    mJoinedCondVar.wait( //
        lk,
        [&] { //
            const auto it = std::find(mJoinedRooms.begin(), mJoinedRooms.end(), roomName);
            if (it != mJoinedRooms.end())
            {
                return true;
            }

            return false;
        });

    return true;
}

bool SecchatClient::sendMessage(const std::string &roomName, const std::string &message)
{
    Proto::Frame frame{// ugly casts...
                       (uint32_t)mMyUserName.size(),
                       (uint32_t)roomName.size(),
                       (uint32_t)message.size()};

    Proto::populateHeader(frame, mMyUserName, roomName);

    // TODO: this message should be signed
    // TODO: this message should be encrypted with sym key

    Proto::populatePayload(frame,
                           Proto::PayloadType::k$$$MessageToRoom,
                           (uint8_t *)message.c_str(), // ugly cast
                           message.size());

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
            case Proto::PayloadType::kNewUserIdAssigned:
                {
                    // TODO: client should receive server's public key here?
                    // TODO: client should wait until this user id is assigned - need mechanism for waiting
                    ui::print("[client] user ID assigned by server: ");
                    ui::printCharacters(payload.payload.get(), payload.size);
                }
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
                ui::print(" ]\n");
                break;
        }
    }
}

void SecchatClient::serverNewUserAnnounce()
{
    const std::string dest{"server"};

    Proto::Frame frame{// ugly casts...
                       (uint32_t)mMyUserName.size(),
                       (uint32_t)dest.size(),
                       (uint32_t)mMyUserName.size()};

    Proto::populateHeader(frame, mMyUserName, dest);

    Proto::populatePayloadNewUser(frame,
                                  mMyUserName,
                                  mKeyMyAsymSign, // ugly cast
                                  mKeyMyAsym);

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    assert(buffer);

    mTransport.sendBlocking(buffer.get(), frame.getSize());
}

void SecchatClient::serverJoinRoom(const std::string &roomName)
{
    Proto::Frame frame{
        // ugly casts...
        (uint32_t)mMyUserName.size(), // src
        (uint32_t)roomName.size(),    // dst
        (uint32_t)roomName.size()     // payload
    };

    Proto::populateHeader(frame, mMyUserName, roomName);

    Proto::populatePayload(frame,
                           Proto::PayloadType::kJoinChatRoom,
                           (uint8_t *)roomName.c_str(), // ugly cast
                           roomName.size());

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    assert(buffer);

    mTransport.sendBlocking(buffer.get(), frame.getSize());
}

void SecchatClient::handleChatRoomJoined(Proto::Frame &frame)
{
    Proto::Payload &payload = frame.getPayload();

    std::string justJoinedChatRoomName;
    justJoinedChatRoomName.assign((char *)payload.payload.get(), payload.size);

    {
        std::lock_guard<std::mutex> lk{mJoinedCondVarMutex};
        mJoinedRooms.push_back(justJoinedChatRoomName);
    }

    mJoinedCondVar.notify_all();
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
