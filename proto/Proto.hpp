#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class Proto
{
public:
    // TODO: how to ensure the user/owner is who he claims to be

    // Frame {
    //      { header - contains payload count },
    //      { payloadType } { payloadSize } { payload }
    //      { payloadType } { payloadSize } { payload }
    //      ...
    // }

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
        //    private: // TODO: fixme
        uint64_t protoVersion;
        uint64_t timestampSend; // timestamped when sending

        uint32_t sourceSize;
        char *source;

        uint32_t destinationSize;
        char *destination;

        uint32_t payloadCount;

        friend class Proto;
    };

    struct Payload
    {
        //    private: // TODO: fixme
        PayloadType type;
        uint32_t payloadSize;
        uint8_t *payload;

        friend class Proto;
    };

    struct Frame
    {
    public:
        uint32_t getSize() const;

        //    private: // TODO: fixme
        Header *header; // TODO: reference?
        std::vector<Payload *> payloads;

        friend class Proto;
    };

    // source & dest pointers must be valid up until
    // serialization - data not copied
    static Header createHeader( //
        const std::string &source,
        const std::string &destination);

    // payload pointer must be valid up until
    // serialization - data not copied
    static Payload createPayload( //
        PayloadType type,
        uint8_t *const payload,
        const uint32_t payloadSize);

    // TODO: support multiple payloads...
    // header and payload must be valud up until
    // serialization - data not copied
    static Frame createFrame( //
        Header &header,
        Payload &payload);

    static bool serialize(const Frame &frame, std::shared_ptr<uint8_t[]> buffer);
    static bool deserialize(const uint8_t *const buffer, Frame &frame);

    // serialize() - streams?
    // deserialize() - streams?
};
