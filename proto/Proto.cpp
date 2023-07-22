#include "Proto.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>

namespace proto
{

constexpr uint64_t genProtoVersion(const uint32_t major, const uint32_t minor)
{
    return (((uint64_t)major) << 32) | (((uint64_t)minor));
}

constexpr uint64_t kProtoVersionCurrent = genProtoVersion(1, 0);

utils::ByteArray serializeFrame(proto::Frame &frame)
{
    frame.set_protoversion(kProtoVersionCurrent);

    auto currentTime = //
        std::chrono::system_clock::now();
    auto currentTimeUnixMicro =                                //
        std::chrono::duration_cast<std::chrono::microseconds>( //
            currentTime.time_since_epoch())
            .count();

    frame.set_timestampsend(currentTimeUnixMicro);

    utils::ByteArray ba{(uint32_t)frame.ByteSizeLong()};

    const bool ok = frame.SerializeToArray(ba, ba);
    assert(ok);

    return ba;
}

Frame deserializeFrame(const utils::ByteArray &ba)
{
    Frame frame;

    const bool ok = frame.ParseFromArray(ba, ba);
    assert(ok);

    return frame;
}

Frame deserializeFrame(const uint8_t *const data, const uint32_t dataSize)
{
    Frame frame;

    const bool ok = frame.ParseFromArray(data, dataSize);
    assert(ok);

    return frame;
}

} // namespace proto
