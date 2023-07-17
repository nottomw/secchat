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

class Proto
{
public:
    enum class PayloadType
    {
        kNone,

        // ------ PLAINTEXT messages, not signed

        kUserConnect, // from user, contains pub keys (sign & encrypt)

        // ------ ENCRYPTED asym only

        kUserConnectAck, // from server, contains servers pub keys (sign & encrypt), encrypted with user pub key

        // ------ ENCRYPTED asym only, signed asym by sender:

        kNewSymKeyRequest, // from server, request new sym key generation and broadcast to all users

        kJoinChatRoom,   // from user
        kLeaveChatRoom,  // from user
        kChatRoomJoined, // from server, acknowledge room join

        // ------ ENCRYPTED messages asym, signed asym by sender:

        k$$$ChatGroupSymKeyRequest,  // from user, request asym key, sent to random N users
        k$$$ChatGroupSymKeyResponse, // from user, respond with asym key encrypted with requesting user pubkey

        // ------ ENCRYPTED messages sym, signed asym by sender:

        k$$$MessageToRoom, // from user, encrypted sym, signed asym
        k$$$MessageToUser, // from user, encrypted sym, signed asym

        k$$$UserAsymKeyChanged, // send by user - new pubkey, signed with old asym key, encrypted sym
    };

    struct Header
    {
    public:
        uint64_t protoVersion;
        uint64_t timestampSend; // timestamped when sending

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
        Frame(const uint32_t sourceSize,
              const uint32_t destinationSize,
              const uint32_t payloadSize); // create frame for serialize

        Frame(const Frame &) = default;
        Frame(Frame &&) = default;
        Frame &operator=(const Frame &) = default;
        Frame &operator=(Frame &&) = default;
        ~Frame() = default;

        uint32_t getSize() const;
        Header &getHeader();
        Payload &getPayload();

    private:
        Frame(); // create frame for deserialize

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
        const crypto::KeyAsym &key);

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
};
