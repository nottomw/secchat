#include "SecchatClient.hpp"

#include "Utils.hpp"

#include <chrono>
#include <iostream>
#include <thread>

SecchatClient::SecchatClient()
    : mCrypto{}
    , mTransport{}
    , mReaderShouldRun{true}
{
    if (!mCrypto.init())
    {
        printf("Crypto init failed\n");
    }
}

void SecchatClient::connectToServer(const std::string &ipAddr, const uint16_t port)
{
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

    // If this is first user to join the room, he is considered the room owner:
    // - owner generates asymetric group chat key

    // When new user joins:
    // - new user sends pub key to the server
    // - randomly selected user (usr1) is requested to send room key to new user
    // - usr1 encrypts group chat key with pub key
    // - usr1 sends the encrypted group chat key to new user

    // send "new user"
    // receive my ID

    // send "join chat room"
    // receive success/failure

    serverNewUserAnnounce();
}

bool SecchatClient::joinRoom(const std::string &roomName)
{
    printf("[client] joining room %s\n", roomName.c_str());

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

void SecchatClient::sendMessage(const std::string &roomName, const std::string &message)
{
    printf("[client] sending: %s\n", message.c_str());

    Proto::Frame frame{// ugly casts...
                       (uint32_t)mMyUserName.size(),
                       (uint32_t)roomName.size(),
                       (uint32_t)message.size()};

    Proto::populateHeader(frame, mMyUserName, roomName);

    // TODO: this message should be encrypted with sym key

    Proto::populatePayload(frame,
                           Proto::PayloadType::k$$$MessageToRoom,
                           (uint8_t *)message.c_str(), // ugly cast
                           message.size());

    std::unique_ptr<uint8_t[]> buffer = Proto::serialize(frame);
    assert(buffer);

    const bool sendOk = mTransport.sendBlocking(buffer.get(), frame.getSize());
    assert(sendOk == true);
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
                printf("[client] user ID assigned by server: ");
                utils::printCharacters(payload.payload.get(), payload.size);
                break;

            case Proto::PayloadType::kChatRoomJoined:
                handleChatRoomJoined(framesIt);
                break;

            case Proto::PayloadType::k$$$MessageToRoom:
                handleMessageToRoom(framesIt);
                break;

            default:
                printf("[server] incorrect frame, NOT HANDLED: ");
                utils::printCharactersHex(data, dataLen);
                break;
        }
    }
}

void SecchatClient::serverNewUserAnnounce()
{
    const std::string dest{"testdestserver"};

    Proto::Frame frame{// ugly casts...
                       (uint32_t)mMyUserName.size(),
                       (uint32_t)dest.size(),
                       (uint32_t)mMyUserName.size()};

    Proto::populateHeader(frame, mMyUserName, dest);

    // TODO: this payload should contain user name & public key
    Proto::populatePayload(frame,
                           Proto::PayloadType::kNewUser,
                           (uint8_t *)mMyUserName.c_str(), // ugly cast
                           mMyUserName.size());

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

    userName.assign(header.source.get(), header.sourceSize);
    roomName.assign(header.destination.get(), header.destinationSize);
    message.assign((char *)payload.payload.get(), payload.size);

    // Since no proper UI is implemented, for now just display the message...
    printf("[%s] <%s> %s\n", //
           roomName.c_str(),
           userName.c_str(),
           message.c_str());
    fflush(stdout);
}
