#pragma once

#include "Crypto.hpp"
#include "SecProto.pb.h"
#include "Utils.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace proto
{

constexpr uint64_t genProtoVersion(const uint32_t major, const uint32_t minor)
{
    return (((uint64_t)major) << 32) | (((uint64_t)minor));
}

constexpr uint64_t kProtoVersionCurrent = genProtoVersion(1, 0);

enum class PayloadType
{
    kNone,

    // ------ PLAINTEXT messages, not signed

    kUserConnect, // from user, contains pub keys (sign & encrypt)

    // ------ ENCRYPTED asym only

    kUserConnectAck, // from server, contains servers pub keys (sign & encrypt), encrypted with
                     // user pub key

    // ------ ENCRYPTED asym only, signed asym by sender:

    kNewSymKeyRequest, // from server, request new sym key generation from specific user

    kChatRoomJoin,   // from user
    kChatRoomJoined, // from server, acknowledge room join
    kChatRoomLeave,  // from user

    // TODO: user should get a prompt (yes/no) to confirm he wants to provide the keys?
    kChatGroupCurrentSymKeyRequest,  // from user, request sym key, sent to server, server
                                     // forwards
    kUserPubKeys,                    // from server, send other user pub key to requesting user
    kChatGroupCurrentSymKeyResponse, // from user, respond with asym key encrypted with
                                     // requesting user pubkey

    // ------ ENCRYPTED messages sym, signed asym by sender:

    k$$$MessageToRoom, // from user, encrypted sym, signed asym
    k$$$MessageToUser, // from user, encrypted sym, signed asym

    k$$$UserAsymKeyChanged, // send by user - new pubkey, signed with old asym key, encrypted
                            // sym
};

void serialize(proto::Frame &frame);

}; // namespace proto
