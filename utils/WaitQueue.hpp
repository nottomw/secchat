#pragma once

#include "Utils.hpp"

#include <cstdint>
#include <future>
#include <vector>

namespace utils
{

// Not greatest that the events need to be hardcoded here, maybe fix later...
enum class WaitEventType
{
    kUserConnectAck,
    kUserJoined
};

class WaitQueue
{
public:
    std::future<utils::ByteArray> waitFor( //
        const WaitEventType type,
        std::string &&matchStr);

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
