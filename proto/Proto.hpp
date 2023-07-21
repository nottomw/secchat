#pragma once

#include "Crypto.hpp"
#include "Utils.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace crypto
{
struct KeyAsym;
}

// TODO: all of this needs to be thoroughly size-checked
// TODO: use something like protobuf instead of this horrendous code
// TODO: some payloads are actualy filled in by the client, should be fixed

class Proto
{
public:
    enum class PayloadType
    {
        kNone,

        // ------ PLAINTEXT messages, not signed

        kUserConnect, // from user, contains pub keys (sign & encrypt)

        // ------ ENCRYPTED asym only

        kUserConnectAck, // from server, contains servers pub keys (sign & encrypt), encrypted with
                         // user pub key

        // ------ ENCRYPTED asym only, signed asym by sender:

        kNewSymKeyRequest, // from server, request new sym key generation and broadcast to all users

        kChatRoomJoin,   // from user
        kChatRoomJoined, // from server, acknowledge room join
        kChatRoomLeave,  // from user

        // TODO: requested user should get a prompt (yes/no) to confirm he wants to provide the keys
        kChatGroupSymKeyRequest, // from user, request asym key, sent to random N users (or chat
                                 // owner?)
        kChatGroupSymKeyReplyUserKey, // from server, send other user pub key to requesting user
        kChatGroupSymKeyResponse, // from user, respond with asym key encrypted with requesting user
                                  // pubkey

        // ------ ENCRYPTED messages sym, signed asym by sender:

        k$$$MessageToRoom, // from user, encrypted sym, signed asym
        k$$$MessageToUser, // from user, encrypted sym, signed asym

        k$$$UserAsymKeyChanged, // send by user - new pubkey, signed with old asym key, encrypted
                                // sym
    };

    // Header is never encrypted - sent plain text.
    struct Header
    {
    public:
        uint64_t protoVersion;
        uint64_t timestampSend; // timestamped when sending

        // TODO: the source & destination should have some "max size" and
        // the buffer should always be allocated to this max size, same for payload.
        uint32_t sourceSize;
        std::unique_ptr<char[]> source;

        uint32_t destinationSize;
        std::unique_ptr<char[]> destination;

    private:
        Header();

        friend class Proto;
    };

    struct Payload
    {
    public:
        PayloadType type;
        uint32_t size;
        std::unique_ptr<uint8_t[]> payload;

    private:
        Payload();

        friend class Proto;
    };

    struct Frame
    {
    public:
        uint32_t getSize() const;
        Header &getHeader();
        Payload &getPayload();

    private:
        Header header;
        Payload payload;

        friend class Proto;
    };

    struct PayloadUserConnect
    {
        std::string userName;
        uint8_t pubSignKey[crypto::kPubKeySignatureByteCount];
        uint8_t pubEncryptKey[crypto::kPubKeyByteCount];
    };

    struct PayloadUserConnectAck
    {
        uint8_t pubSignKey[crypto::kPubKeySignatureByteCount];
        uint8_t pubEncryptKey[crypto::kPubKeyByteCount];
    };

    // Very fishy - same frame used for both join request and response
    struct PayloadJoinReqAck
    {
        uint8_t newRoom; // 1 or 0
        uint32_t roomNameSize;
        std::string roomName;
    };

    struct PayloadRequestCurrentSymKey
    {
        uint32_t roomNameSize;
        std::string roomName;
        uint8_t pubEncryptKey[crypto::kPubKeyByteCount];
    };

    static void populateHeader( //
        Frame &frame,
        const std::string &source,
        const std::string &destination);

    static void populatePayload( //
        Frame &frame,
        PayloadType type,
        uint8_t *const payload,
        const uint32_t payloadSize);

    static void populatePayloadUserConnect( //
        Frame &frame,
        const std::string &userName,
        const crypto::KeyAsymSignature &keySign,
        const crypto::KeyAsym &key);

    static void populatePayloadUserConnectAck( //
        Frame &frame,
        const crypto::KeyAsymSignature &keySign,
        const crypto::KeyAsym &key,
        const crypto::KeyAsym &payloadEncryptionKey);

    static void populatePayloadChatRoomJoinOrAck( //
        Frame &frame,
        const std::string &roomName,
        const crypto::KeyAsymSignature &payloadSignKey,
        const crypto::KeyAsym &payloadEncryptKey,
        const bool isJoinAck = false,
        const bool newRoomCreated = false);

    static void populatePayloadNewSymKeyRequest( //
        Proto::Frame &frame,
        const std::string &roomName,
        const crypto::KeyAsymSignature &payloadSignKey,
        const crypto::KeyAsym &payloadEncryptKey);

    static void populatePayloadCurrentSymKeyRequest( //
        Proto::Frame &frame,
        const std::string &roomName,
        const crypto::KeyAsymSignature &payloadSignKey,
        const crypto::KeyAsym &payloadEncryptKey,
        const crypto::KeyAsym &payloadEncryptKeyToSend);

    static void populatePayloadCurrentSymKeyResponse( //
        Proto::Frame &frame,
        const crypto::KeySym &chatGroupSymKey,
        const crypto::KeyAsymSignature &payloadSignKey,
        const crypto::KeyAsym &payloadEncryptKey);

    static std::unique_ptr<uint8_t[]> serialize( //
        const Frame &frame);

    static std::vector<Frame> deserialize( //
        const uint8_t *const buffer,
        const uint32_t bufferSize);

    static utils::ByteArray serializeUserConnect( //
        const PayloadUserConnect &payload);

    static PayloadUserConnect deserializeUserConnect( //
        const uint8_t *const buffer,
        const uint32_t bufferSize);

    static PayloadUserConnectAck deserializeUserConnectAck( //
        const uint8_t *const buffer,
        const uint32_t bufferSize);

    static utils::ByteArray serializeJoinReqAck( //
        const PayloadJoinReqAck &payload);

    static PayloadJoinReqAck deserializeJoinReqAck( //
        const uint8_t *const buffer,
        const uint32_t bufferSize);

    static utils::ByteArray serializeRequestCurrentSymKey( //
        const PayloadRequestCurrentSymKey &payload);

    static PayloadRequestCurrentSymKey deserializeRequestCurrentSymKey( //
        const uint8_t *const buffer,
        const uint32_t bufferSize);
};
