#include "WaitQueue.hpp"

namespace utils
{

std::future<ByteArray> WaitQueue::waitFor( //
    const WaitEventType type,
    std::string &&matchStr)
{
    std::promise<ByteArray> prom;
    std::future<ByteArray> fut = prom.get_future();

    WaitObject obj;
    obj.mEventType = type;
    obj.mPromise = std::move(prom);
    obj.mMatchStr = std::move(matchStr);

    {
        std::unique_lock<std::mutex> lk{mWaitObjectsMutex};
        mWaitObjects.push_back(std::move(obj));
    }

    return fut;
}

void WaitQueue::complete( //
    const WaitEventType type,
    const std::string &matchStr,
    ByteArray &&responseMetadata)
{
    {
        // pretty hardcore but good enough for now
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
