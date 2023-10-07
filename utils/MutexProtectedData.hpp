#pragma once

#include <functional>
#include <mutex>

template <typename TData>
class MutexProtectedData
{
public:
    using AccessorFn = std::function<void(TData &data)>;

    MutexProtectedData(const MutexProtectedData &oth)
        : mData{oth.mData}
    {
    }

    MutexProtectedData(MutexProtectedData &&oth)
        : mData{oth.mData}
    {
    }

    MutexProtectedData &operator=(const MutexProtectedData &oth)
    {
        mData = oth;
        return *this;
    }

    MutexProtectedData &operator=(MutexProtectedData &&oth)
    {
        mData = oth;
        return *this;
    }

    ~MutexProtectedData() = default;

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
