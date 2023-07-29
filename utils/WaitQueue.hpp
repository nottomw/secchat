#pragma once

#include "Utils.hpp"

#include <chrono>
#include <cstdint>
#include <future>
#include <optional>
#include <vector>

namespace utils
{

// Not greatest that the events need to be hardcoded here, maybe fix later...
enum class WaitEventType
{
    kUserConnectAck,
    kUserJoined,
    kSymmetricKeyReceived
};

class WaitQueue
{
public:
    // No data in optional<> means timeout
    std::optional<utils::ByteArray> waitFor( //
        const WaitEventType type,
        std::string &&matchStr,
        const uint32_t timeoutSeconds);

    void complete( //
        const WaitEventType type,
        const std::string &matchStr,
        utils::ByteArray &&responseMetadata = {});

private:
    struct WaitObject
    {
        WaitEventType mEventType;
        std::promise<utils::ByteArray> mPromise;
        std::string mMatchStr;
    };

    std::mutex mWaitObjectsMutex;
    std::vector<WaitObject> mWaitObjects;
};

} // namespace utils
