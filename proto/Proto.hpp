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

utils::ByteArray serializeFrame(proto::Frame &frame);

Frame deserializeFrame(const utils::ByteArray &ba);
Frame deserializeFrame(const uint8_t *const data, const uint32_t dataSize);

template <typename T>
utils::ByteArray serializePayload(const T &pay)
{
    utils::ByteArray ba{(uint32_t)pay.ByteSizeLong()};

    const bool ok = pay.SerializeToArray(ba, ba);
    assert(ok);

    return ba;
}

template <typename T>
T deserializePayload(const uint8_t *const data, const uint32_t dataSize)
{
    T pay;

    const bool ok = pay.ParseFromArray(data, dataSize);
    assert(ok);

    return pay;
}

template <typename T>
T deserializePayload(const utils::ByteArray &ba)
{
    return deserializePayload<T>(ba, ba);
}

template <typename T>
T deserializePayload(const char *const data, const uint32_t dataSize)
{
    return deserializePayload<T>((uint8_t *)data, dataSize);
}

}; // namespace proto
