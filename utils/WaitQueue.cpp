#include "WaitQueue.hpp"

namespace utils
{

std::optional<utils::ByteArray> WaitQueue::waitFor( //
    const WaitEventType type,
    const std::string &matchStr,
    const uint32_t timeoutSeconds)
{
    std::promise<ByteArray> prom;
    std::future<ByteArray> fut = prom.get_future();

    WaitObject obj;
    obj.mEventType = type;
    obj.mPromise = std::move(prom);
    obj.mMatchStr = matchStr;

    {
        std::unique_lock<std::mutex> lk{mWaitObjectsMutex};
        mWaitObjects.push_back(std::move(obj));
    }

    auto status = fut.wait_for(std::chrono::seconds(timeoutSeconds));
    if (status != std::future_status::ready)
    {
        return std::nullopt;
    }

    return fut.get();
}

void WaitQueue::complete( //
    const WaitEventType type,
    const std::string &matchStr,
    ByteArray &&responseMetadata)
{
    {
        std::unique_lock<std::mutex> lk{mWaitObjectsMutex};

        for (auto waitObjIt = mWaitObjects.begin(); //
             waitObjIt != mWaitObjects.end();
             /* incremented in body */)
        {
            if ((waitObjIt->mEventType == type) && //
                (waitObjIt->mMatchStr == matchStr))
            {
                // match
                waitObjIt->mPromise.set_value(std::move(responseMetadata));
                waitObjIt = mWaitObjects.erase(waitObjIt);
            }
            else
            {
                waitObjIt++;
            }
        }
    }
}

} // namespace utils
