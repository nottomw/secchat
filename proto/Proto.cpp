#include "Proto.hpp"

#include <cstdio>
#include <cstring>

constexpr uint64_t genProtoVersion(const uint32_t major, const uint32_t minor)
{
    return (((uint64_t)major) << 32) | (((uint64_t)minor));
}

constexpr uint64_t kProtoVersionCurrent = genProtoVersion(1, 0);

Proto::Header Proto::createHeader( //
    const std::string &source,
    const std::string &destination)
{
    Header header;
    header.protoVersion = kProtoVersionCurrent;
    header.timestampSend = 0U;              // populated later
    header.source = (char *)source.c_str(); // ugly casts
    header.sourceSize = source.size();
    header.destination = (char *)destination.c_str();
    header.destinationSize = destination.size();
    header.payloadCount = 0U; // populated later

    return header;
}

Proto::Payload Proto::createPayload(Proto::PayloadType type, uint8_t *const payload, const uint32_t payloadSize)
{
    Payload p;
    p.type = type;
    p.payloadSize = payloadSize;
    p.payload = payload;

    return p;
}

Proto::Frame Proto::createFrame(Proto::Header &header, Proto::Payload &payload)
{
    header.payloadCount = 1U;

    Frame frame;
    frame.header = &header;
    frame.payloads.push_back(&payload);

    return frame;
}

bool Proto::serialize(const Proto::Frame &frame, std::shared_ptr<uint8_t[]> buffer)
{
    if (!buffer)
    {
        return false;
    }

    uint8_t *buf = buffer.get(); // move buffer around

    // Serialize the header...
    memcpy(buf, &frame.header->protoVersion, sizeof(Header::protoVersion));
    buf += sizeof(Header::protoVersion);

    memcpy(buf, &frame.header->timestampSend, sizeof(Header::timestampSend));
    buf += sizeof(Header::timestampSend);

    memcpy(buf, &frame.header->sourceSize, sizeof(Header::sourceSize));
    buf += sizeof(Header::sourceSize);

    memcpy(buf, frame.header->source, frame.header->sourceSize);
    buf += frame.header->sourceSize;

    memcpy(buf, &frame.header->destinationSize, sizeof(Header::destinationSize));
    buf += sizeof(Header::destinationSize);

    memcpy(buf, frame.header->destination, frame.header->destinationSize);
    buf += frame.header->destinationSize;

    memcpy(buf, &frame.header->payloadCount, sizeof(Header::payloadCount));
    buf += sizeof(Header::payloadCount);

    // Serialize the payloads...
    for (const auto &payloadIt : frame.payloads)
    {
        memcpy(buf, &payloadIt->type, sizeof(Payload::type));
        buf += sizeof(Payload::type);

        memcpy(buf, &payloadIt->payloadSize, sizeof(Payload::payloadSize));
        buf += sizeof(Payload::payloadSize);

        memcpy(buf, payloadIt->payload, payloadIt->payloadSize);
        buf += payloadIt->payloadSize;
    }

    return true;
}

bool Proto::deserialize(const uint8_t *const buffer, Proto::Frame &frame)
{
    if (buffer == nullptr)
    {
        return false;
    }

    const uint8_t *buf = buffer; // copy the pointer so it can be moved

    // Deserialize the header...
    memcpy(&frame.header->protoVersion, buf, sizeof(Header::protoVersion));
    buf += sizeof(Header::protoVersion);

    memcpy(&frame.header->timestampSend, buf, sizeof(Header::timestampSend));
    buf += sizeof(Header::timestampSend);

    memcpy(&frame.header->sourceSize, buf, sizeof(Header::sourceSize));
    buf += sizeof(Header::sourceSize);

    // TODO: memleak
    frame.header->source = new char[frame.header->sourceSize];
    memcpy(frame.header->source, buf, frame.header->sourceSize);
    buf += frame.header->sourceSize;

    memcpy(&frame.header->destinationSize, buf, sizeof(Header::destinationSize));
    buf += sizeof(Header::destinationSize);

    // TODO: memleak
    frame.header->destination = new char[frame.header->destinationSize];
    memcpy(frame.header->destination, buf, frame.header->destinationSize);
    buf += frame.header->destinationSize;

    memcpy(&frame.header->payloadCount, buf, sizeof(Header::payloadCount));
    buf += sizeof(Header::payloadCount);

    // Deserialize the payloads...
    for (size_t i = 0; i < frame.header->payloadCount; ++i)
    {
        Payload *payload = new Payload; // TODO: memleak

        memcpy(&payload->type, buf, sizeof(Payload::type));
        buf += sizeof(Payload::type);

        memcpy(&payload->payloadSize, buf, sizeof(Payload::payloadSize));
        buf += sizeof(Payload::payloadSize);

        // TODO: memleak
        payload->payload = new uint8_t[payload->payloadSize];
        memcpy(payload->payload, buf, payload->payloadSize);
        buf += payload->payloadSize;

        frame.payloads.push_back(payload);
    }

    return true;
}

uint32_t Proto::Frame::getSize() const
{
    constexpr uint32_t kHeaderSizeStatic = //
        sizeof(Header::protoVersion) +     //
        sizeof(Header::timestampSend) +    //
        sizeof(Header::sourceSize) +       //
        sizeof(Header::destinationSize) +  //
        sizeof(Header::payloadCount);

    constexpr uint32_t kPayloadSizeStatic = //
        sizeof(Payload::type) +             //
        sizeof(Payload::payloadSize);

    const uint32_t headerSize = //
        kHeaderSizeStatic +     //
        header->sourceSize +    //
        header->destinationSize;

    uint32_t payloadSize = 0U;
    for (const auto &it : payloads)
    {
        payloadSize +=           //
            kPayloadSizeStatic + //
            it->payloadSize;
    }

    const uint32_t frameSize = headerSize + payloadSize;
    return frameSize;
}
