#include "Proto.hpp"

#include <cassert>
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
    frame.header.timestampSend = 0U; // populated later

    memcpy(frame.header.source.get(), source.c_str(), source.size());

    frame.header.sourceSize = source.size();

    memcpy(frame.header.destination.get(), destination.c_str(), destination.size());

    frame.header.destinationSize = destination.size();
}

void Proto::populatePayload( //
    Frame &frame,
    Proto::PayloadType type,
    uint8_t *const payload,
    const uint32_t payloadSize)
{
    frame.payload.type = type;
    frame.payload.size = payloadSize;

    memcpy(frame.payload.payload.get(), payload, payloadSize);
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

Proto::Frame::Frame( //
    const uint32_t sourceSize,
    const uint32_t destinationSize,
    const uint32_t payloadSize)
{
    header.source = std::unique_ptr<char[]>(new char[sourceSize]);
    header.destination = std::unique_ptr<char[]>(new char[destinationSize]);
    payload.payload = std::unique_ptr<uint8_t[]>(new uint8_t[payloadSize]);
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

Proto::Frame::Frame()
{
    // That's an empty frame - memory allocated during deserialize
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
