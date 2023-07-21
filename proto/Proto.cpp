#include "Proto.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>

constexpr uint64_t genProtoVersion(const uint32_t major, const uint32_t minor)
{
    return (((uint64_t)major) << 32) | (((uint64_t)minor));
}

constexpr uint64_t kProtoVersionCurrent = genProtoVersion(1, 0);

void Proto::populateHeader( //
    Frame &frame,
    const std::string &source,
    const std::string &destination)
{
    frame.header.protoVersion = kProtoVersionCurrent;

    auto currentTime = //
        std::chrono::system_clock::now();
    auto currentTimeUnixMicro =                                //
        std::chrono::duration_cast<std::chrono::microseconds>( //
            currentTime.time_since_epoch())
            .count();

    frame.header.timestampSend = currentTimeUnixMicro; // should be populated later

    frame.header.source = std::make_unique<char[]>(source.size());
    memcpy(frame.header.source.get(), source.c_str(), source.size());

    frame.header.sourceSize = source.size();

    frame.header.destination = std::make_unique<char[]>(destination.size());
    memcpy(frame.header.destination.get(), destination.c_str(), destination.size());

    frame.header.destinationSize = destination.size();
}

void Proto::populatePayload( //
    Frame &frame,
    Proto::PayloadType type,
    uint8_t *const payload,
    const uint32_t payloadSize)
{
    frame.payload.payload = std::unique_ptr<uint8_t[]>(new uint8_t[payloadSize]);

    frame.payload.type = type;
    frame.payload.size = payloadSize;

    memcpy(frame.payload.payload.get(), payload, payloadSize);
}

void Proto::populatePayloadUserConnect( //
    Proto::Frame &frame,
    const std::string &userName,
    const crypto::KeyAsymSignature &keySign,
    const crypto::KeyAsym &key)
{
    PayloadUserConnect payloadUserConnect;
    payloadUserConnect.userName = userName;

    memcpy(payloadUserConnect.pubSignKey, keySign.mKeyPub, crypto::kPubKeySignatureByteCount);
    memcpy(payloadUserConnect.pubEncryptKey, key.mKeyPub, crypto::kPubKeyByteCount);

    auto buffer = serializeUserConnect(payloadUserConnect);

    frame.payload.type = PayloadType::kUserConnect;
    frame.payload.payload = std::move(buffer.data);
    frame.payload.size = buffer.dataSize;
}

void Proto::populatePayloadUserConnectAck( //
    Proto::Frame &frame,
    const crypto::KeyAsymSignature &keySign,
    const crypto::KeyAsym &key,
    const crypto::KeyAsym &payloadEncryptionKey)
{
    const uint32_t payloadSize = //
        crypto::kPubKeySignatureByteCount + crypto::kPubKeyByteCount;

    auto tmpBuffer = std::make_unique<uint8_t[]>(payloadSize);

    uint8_t *const tmpBufferAddr = tmpBuffer.get();
    uint8_t *const signOff = tmpBufferAddr;
    uint8_t *const encrOff = tmpBufferAddr + crypto::kPubKeySignatureByteCount;

    memcpy(signOff, keySign.mKeyPub, crypto::kPubKeySignatureByteCount);
    memcpy(encrOff, key.mKeyPub, crypto::kPubKeyByteCount);

    crypto::EncryptedData encrypted =
        crypto::asymEncrypt(payloadEncryptionKey, tmpBufferAddr, payloadSize);

    frame.payload.type = PayloadType::kUserConnectAck;
    frame.payload.payload = std::move(encrypted.data);
    frame.payload.size = encrypted.dataSize;
}

void Proto::populatePayloadChatRoomJoinOrAck( //
    Proto::Frame &frame,
    const std::string &roomName,
    const crypto::KeyAsymSignature &payloadSignKey,
    const crypto::KeyAsym &payloadEncryptKey,
    const bool isJoinAck,
    const bool newRoomCreated)
{
    //    const bool joinAckNewRoom = newRoomCreated && isJoinAck;
    //    const bool joinAckOldRoom = newRoomCreated && !isJoinAck;
    //    const bool joinReq = !newRoomCreated && !isJoinAck;
    //    assert(joinAckNewRoom || joinAckOldRoom || joinReq);

    PayloadJoinReqAck join;
    join.newRoom = newRoomCreated;
    join.roomNameSize = roomName.size();
    join.roomName = roomName;

    utils::ByteArray joinSerialized = serializeJoinReqAck(join);

    crypto::SignedData signedData = //
        crypto::sign(               //
            payloadSignKey,
            joinSerialized.data.get(),
            joinSerialized.dataSize);

    crypto::EncryptedData encryptedData =      //
        crypto::asymEncrypt(payloadEncryptKey, //
                            signedData.data.get(),
                            signedData.dataSize);

    Payload &pay = frame.getPayload();

    if (isJoinAck)
    {
        pay.type = PayloadType::kChatRoomJoined;
    }
    else
    {
        pay.type = PayloadType::kChatRoomJoin;
    }

    pay.payload = std::move(encryptedData.data);
    pay.size = encryptedData.dataSize;
}

void Proto::populatePayloadNewSymKeyRequest( //
    Proto::Frame &frame,
    const std::string &roomName,
    const crypto::KeyAsymSignature &payloadSignKey,
    const crypto::KeyAsym &payloadEncryptKey)
{
    Proto::Payload &pay = frame.getPayload();

    pay.type = PayloadType::kNewSymKeyRequest;

    crypto::SignedData signedData = //
        crypto::sign(               //
            payloadSignKey,
            (uint8_t *)roomName.c_str(),
            roomName.size());

    crypto::EncryptedData encryptedData =      //
        crypto::asymEncrypt(payloadEncryptKey, //
                            signedData.data.get(),
                            signedData.dataSize);

    pay.payload = std::move(encryptedData.data);
    pay.size = encryptedData.dataSize;
}

void Proto::populatePayloadCurrentSymKeyRequest( //
    Proto::Frame &frame,
    const std::string &roomName,
    const crypto::KeyAsymSignature &payloadSignKey,
    const crypto::KeyAsym &payloadEncryptKey)
{
    PayloadRequestCurrentSymKey req;
    req.roomNameSize = roomName.size();
    req.roomName = roomName;

    auto reqSerialized = serializeRequestCurrentSymKey(req);

    auto signedReq = //
        crypto::sign(payloadSignKey, reqSerialized.data.get(), reqSerialized.dataSize);

    auto encryptedReq =
        crypto::asymEncrypt(payloadEncryptKey, signedReq.data.get(), signedReq.dataSize);

    Payload &pay = frame.getPayload();
    pay.type = Proto::PayloadType::kChatGroupSymKeyRequest;
    pay.payload = std::move(encryptedReq.data);
    pay.size = encryptedReq.dataSize;
}

void Proto::populatePayloadMessage( //
    Proto::Frame &frame,
    const std::string &message,
    const crypto::KeyAsymSignature &payloadSignKey,
    const crypto::KeySym &groupChatKey)
{
    Payload &pay = frame.getPayload();

    PayloadMessage messagePayload;

    auto nonceBa = crypto::symEncryptGetNonce();
    messagePayload.nonce = std::move(nonceBa);

    const uint32_t messageSize = message.size();
    crypto::SignedData signedData = //
        crypto::sign(               //
            payloadSignKey,
            (uint8_t *)message.c_str(),
            messageSize);

    crypto::EncryptedData encryptedData = //
        crypto::symEncrypt(groupChatKey,  //
                           signedData.data.get(),
                           signedData.dataSize,
                           messagePayload.nonce);

    messagePayload.msg.data = std::move(encryptedData.data);
    messagePayload.msg.dataSize = encryptedData.dataSize;

    utils::ByteArray serializedMessage = serializeMessage(messagePayload);

    pay.type = Proto::PayloadType::k$$$MessageToRoom;
    pay.payload = std::move(serializedMessage.data);
    pay.size = serializedMessage.dataSize;
}

std::unique_ptr<uint8_t[]> Proto::serialize(const Proto::Frame &frame)
{
    auto retBuf = std::unique_ptr<uint8_t[]>(new uint8_t[frame.getSize()]);
    uint8_t *buf = retBuf.get();

    // Serialize the header...
    memcpy(buf, &frame.header.protoVersion, sizeof(Header::protoVersion));
    buf += sizeof(Header::protoVersion);

    memcpy(buf, &frame.header.timestampSend, sizeof(Header::timestampSend));
    buf += sizeof(Header::timestampSend);

    memcpy(buf, &frame.header.sourceSize, sizeof(Header::sourceSize));
    buf += sizeof(Header::sourceSize);

    memcpy(buf, frame.header.source.get(), frame.header.sourceSize);
    buf += frame.header.sourceSize;

    memcpy(buf, &frame.header.destinationSize, sizeof(Header::destinationSize));
    buf += sizeof(Header::destinationSize);

    memcpy(buf, frame.header.destination.get(), frame.header.destinationSize);
    buf += frame.header.destinationSize;

    // Serialize the payload...

    memcpy(buf, &frame.payload.type, sizeof(Payload::type));
    buf += sizeof(Payload::type);

    memcpy(buf, &frame.payload.size, sizeof(Payload::size));
    buf += sizeof(Payload::size);

    memcpy(buf, frame.payload.payload.get(), frame.payload.size);

    return retBuf;
}

std::vector<Proto::Frame> Proto::deserialize( //
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    assert(buffer != nullptr);

    std::vector<Proto::Frame> allFrames;

    const uint8_t *buf = buffer; // copy the pointer so it can be moved
    uint32_t bytesLeftToParse = bufferSize;

    while (bytesLeftToParse > 0)
    {
        Proto::Frame frame;

        // Deserialize the header...
        memcpy(&frame.header.protoVersion, buf, sizeof(Header::protoVersion));
        buf += sizeof(Header::protoVersion);

        memcpy(&frame.header.timestampSend, buf, sizeof(Header::timestampSend));
        buf += sizeof(Header::timestampSend);

        memcpy(&frame.header.sourceSize, buf, sizeof(Header::sourceSize));
        buf += sizeof(Header::sourceSize);

        frame.header.source = std::unique_ptr<char[]>(new char[frame.header.sourceSize]);
        memcpy(frame.header.source.get(), buf, frame.header.sourceSize);
        buf += frame.header.sourceSize;

        memcpy(&frame.header.destinationSize, buf, sizeof(Header::destinationSize));
        buf += sizeof(Header::destinationSize);

        frame.header.destination = std::unique_ptr<char[]>(new char[frame.header.destinationSize]);
        memcpy(frame.header.destination.get(), buf, frame.header.destinationSize);
        buf += frame.header.destinationSize;

        // Deserialize the payload...

        memcpy(&frame.payload.type, buf, sizeof(Payload::type));
        buf += sizeof(Payload::type);

        memcpy(&frame.payload.size, buf, sizeof(Payload::size));
        buf += sizeof(Payload::size);

        frame.payload.payload = std::unique_ptr<uint8_t[]>(new uint8_t[frame.payload.size]);
        memcpy(frame.payload.payload.get(), buf, frame.payload.size);
        buf += frame.payload.size;

        bytesLeftToParse -= frame.getSize();
        allFrames.push_back(std::move(frame));
    }

    return allFrames;
}

utils::ByteArray Proto::serializeUserConnect( //
    const Proto::PayloadUserConnect &payload)
{
    constexpr uint32_t usernameSizeSize = sizeof(uint32_t);
    const uint32_t userNameSize = payload.userName.size();

    const uint32_t totalSize =              //
        usernameSizeSize +                  //
        userNameSize +                      //
        crypto::kPubKeySignatureByteCount + //
        crypto::kPubKeyByteCount;           //

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(totalSize);
    uint8_t *bufferPtr = buffer.get();

    std::memcpy(bufferPtr, &userNameSize, usernameSizeSize);
    bufferPtr += usernameSizeSize;

    std::memcpy(bufferPtr, payload.userName.c_str(), userNameSize);
    bufferPtr += userNameSize;

    std::memcpy(bufferPtr, payload.pubSignKey, crypto::kPubKeySignatureByteCount);
    bufferPtr += crypto::kPubKeySignatureByteCount;

    std::memcpy(bufferPtr, payload.pubEncryptKey, crypto::kPubKeyByteCount);

    utils::ByteArray ba;
    ba.data = std::move(buffer);
    ba.dataSize = totalSize;

    return ba;
}

Proto::PayloadUserConnect Proto::deserializeUserConnect( //
    const uint8_t *const buffer,
    const uint32_t /*bufferSize*/)
{
    PayloadUserConnect payload;

    const uint8_t *bufferPtr = buffer;

    uint32_t userNameSize = 0U;
    std::memcpy(&userNameSize, bufferPtr, sizeof(uint32_t));
    bufferPtr += sizeof(uint32_t);

    std::string userName;
    userName.assign((char *)bufferPtr, userNameSize);

    payload.userName = userName;

    bufferPtr += userNameSize;

    std::memcpy(payload.pubSignKey, bufferPtr, crypto::kPubKeySignatureByteCount);
    bufferPtr += crypto::kPubKeySignatureByteCount;

    std::memcpy(payload.pubEncryptKey, bufferPtr, crypto::kPubKeyByteCount);

    return payload;
}

Proto::PayloadUserConnectAck Proto::deserializeUserConnectAck( //
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    assert(bufferSize == (crypto::kPubKeySignatureByteCount + crypto::kPubKeyByteCount));

    PayloadUserConnectAck ack;

    memcpy(ack.pubSignKey, buffer, crypto::kPubKeySignatureByteCount);
    memcpy(ack.pubEncryptKey, buffer + crypto::kPubKeySignatureByteCount, crypto::kPubKeyByteCount);

    return ack;
}

utils::ByteArray Proto::serializeJoinReqAck(const Proto::PayloadJoinReqAck &payload)
{
    const uint32_t roomNameSize = payload.roomName.size();
    const uint32_t paySize =                      //
        sizeof(PayloadJoinReqAck::newRoom) +      //
        sizeof(PayloadJoinReqAck::roomNameSize) + //
        roomNameSize;

    utils::ByteArray ba{paySize};
    uint8_t *bufPtr = ba.data.get();

    memcpy(bufPtr, &payload.newRoom, sizeof(PayloadJoinReqAck::newRoom));
    bufPtr += sizeof(PayloadJoinReqAck::newRoom);

    memcpy(bufPtr, &roomNameSize, sizeof(PayloadJoinReqAck::roomNameSize));
    bufPtr += sizeof(PayloadJoinReqAck::roomNameSize);

    memcpy(bufPtr, payload.roomName.c_str(), roomNameSize);

    return ba;
}

Proto::PayloadJoinReqAck Proto::deserializeJoinReqAck( //
    const uint8_t *const buffer,
    const uint32_t /*bufferSize*/)
{
    Proto::PayloadJoinReqAck payload;

    const uint8_t *bufPtr = buffer;

    memcpy(&payload.newRoom, bufPtr, sizeof(PayloadJoinReqAck::newRoom));
    bufPtr += sizeof(PayloadJoinReqAck::newRoom);

    uint32_t roomNameSize;
    memcpy(&roomNameSize, bufPtr, sizeof(PayloadJoinReqAck::roomNameSize));
    bufPtr += sizeof(PayloadJoinReqAck::roomNameSize);

    payload.roomName.assign((char *)bufPtr, roomNameSize);

    return payload;
}

utils::ByteArray Proto::serializeRequestCurrentSymKey(
    const Proto::PayloadRequestCurrentSymKey &payload)
{
    const uint32_t totalSize =    //
        sizeof(uint32_t) +        //
        payload.roomName.size() + //
        crypto::kPubKeyByteCount;

    utils::ByteArray ba;
    ba.data = std::make_unique<uint8_t[]>(totalSize);
    ba.dataSize = totalSize;

    uint32_t offset = 0;

    memcpy(&ba.data[offset], &payload.roomNameSize, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(&ba.data[offset], payload.roomName.c_str(), payload.roomName.size());

    return ba;
}

Proto::PayloadRequestCurrentSymKey Proto::deserializeRequestCurrentSymKey( //
    const uint8_t *const buffer,
    const uint32_t /*bufferSize*/)
{
    PayloadRequestCurrentSymKey payload;

    memcpy(&payload.roomNameSize, buffer, sizeof(uint32_t));

    payload.roomName.assign( //
        (char *)(buffer + sizeof(uint32_t)),
        payload.roomNameSize);

    return payload;
}

utils::ByteArray Proto::serializeMessage( //
    const Proto::PayloadMessage &payload)
{
    const uint32_t payloadSize = //
        sizeof(uint32_t) +       // nonce size
        payload.nonce.dataSize + //
        sizeof(uint32_t) +       // data size
        payload.msg.dataSize;

    utils::ByteArray ba{payloadSize};
    uint8_t *baPtr = ba.data.get();

    uint32_t offset = 0U;
    memcpy(baPtr, &payload.nonce.dataSize, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(baPtr + offset, payload.nonce.data.get(), payload.nonce.dataSize);
    offset += payload.nonce.dataSize;

    memcpy(baPtr + offset, &payload.msg.dataSize, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(baPtr + offset, payload.msg.data.get(), payload.msg.dataSize);

    return ba;
}

Proto::PayloadMessage Proto::deserializeMessage( //
    const uint8_t *const buffer,
    const uint32_t /*bufferSize*/)
{
    PayloadMessage msg;

    uint32_t offset = 0U;

    memcpy(&msg.nonce.dataSize, buffer + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    msg.nonce.data = std::make_unique<uint8_t[]>(msg.nonce.dataSize);

    memcpy(msg.nonce.data.get(), buffer + offset, msg.nonce.dataSize);
    offset += msg.nonce.dataSize;

    memcpy(&msg.msg.dataSize, buffer + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    msg.msg.data = std::make_unique<uint8_t[]>(msg.msg.dataSize);

    memcpy(msg.msg.data.get(), buffer + offset, msg.msg.dataSize);

    return msg;
}

uint32_t Proto::Frame::getSize() const
{
    constexpr uint32_t kHeaderSizeStatic = //
        sizeof(Header::protoVersion) +     //
        sizeof(Header::timestampSend) +    //
        sizeof(Header::sourceSize) +       //
        sizeof(Header::destinationSize);

    constexpr uint32_t kPayloadSizeStatic = //
        sizeof(Payload::type) +             //
        sizeof(Payload::size);

    const uint32_t headerSize = //
        kHeaderSizeStatic +     //
        header.sourceSize +     //
        header.destinationSize;

    const uint32_t payloadSize = //
        kPayloadSizeStatic +     //
        payload.size;

    const uint32_t frameSize = headerSize + payloadSize;
    return frameSize;
}

Proto::Header &Proto::Frame::getHeader()
{
    return header;
}

Proto::Payload &Proto::Frame::getPayload()
{
    return payload;
}

Proto::Payload::Payload()
    : type{PayloadType::kNone}
    , size{0U}
{
}

Proto::Header::Header()
    : protoVersion{kProtoVersionCurrent}
    , timestampSend{0U}
    , sourceSize{0U}
    , destinationSize{0U}
{
}
