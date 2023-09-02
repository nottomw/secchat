#pragma once

#include <mutex>
#include <functional>

// TODO: use MutexProtectedData when needed

template <typename TData>
class MutexProtectedData
{
public:
    using AccessorFn = std::function<void(TData &data)>;

    template <typename... Ts>
    MutexProtectedData(Ts... types)
        : mMtx{}
        , mData{types...}
    {
        // nothing
    }

    void access(const AccessorFn &callback)
    {
        std::lock_guard<std::mutex> lk{mMtx};
        callback(mData);
    }

private:
    std::mutex mMtx;
    TData mData;
};
