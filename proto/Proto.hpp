#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class Proto
{
public:
    // TODO: how to ensure the user/owner is who he claims to be

    enum class PayloadType
    {
        kMessageToServer,
        kMessageFromServer,

        k$$$MessageToRoom, // from user - encrypted sym
        k$$$MessageToUser, // from user - encrypted sym

        kMessageFromServerSymKeyRequest, // contains pub key
        k$$$ChatGroupSymKey,             // from user - encrypted sym

        // server comm payload types
        kNewUser,           // sent by user - contains pub key
        kNewUserIdAssigned, // sent by server

        kJoinChatRoom,   // user
        kChatRoomJoined, // server - room already exists
        kChatRoomCreated // server - new room created
    };

    struct Header
    {
        // private:
        uint64_t protoVersion;
        uint64_t timestampSend; // timestamped when sending

        uint32_t sourceSize;
        std::unique_ptr<char[]> source;

        uint32_t destinationSize;
        std::unique_ptr<char[]> destination;

        friend class Proto;
    };

    struct Payload
    {
        // private:
        PayloadType type;

        uint32_t payloadSize;
        std::unique_ptr<uint8_t[]> payload;

        friend class Proto;
    };

    struct Frame
    {
    public:
        Frame(const uint32_t sourceSize,
              const uint32_t destinationSize,
              const uint32_t payloadSize); // create frame for serialize
        ~Frame();

        Frame(const Frame &) = default;
        Frame(Frame &&) = default;
        // TODO: assignment operators

        uint32_t getSize() const;

        // private:
        Frame(); // create frame for deserialize

        Header header;
        Payload payload;

        friend class Proto;
    };

    // source & dest pointers must be valid up until
    // serialization - data not copied
    static void populateHeader( //
        Frame &frame,
        const std::string &source,
        const std::string &destination);

    // payload pointer must be valid up until
    // serialization - data not copied
    static void populatePayload( //
        Frame &frame,
        PayloadType type,
        uint8_t *const payload,
        const uint32_t payloadSize);

    static std::unique_ptr<uint8_t[]> serialize(const Frame &frame);

    static std::vector<Frame> deserialize( //
        const uint8_t *const buffer,
        const uint32_t bufferSize);

    // serialize() - streams?
    // deserialize() - streams?
};
