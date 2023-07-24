#include "ByteArray.hpp"

#include <cassert>
#include <cstring>

namespace utils
{

utils::ByteArray::ByteArray(const uint32_t size)
    : mMode{Mode::kCopy}
    , mDataRaw{nullptr}
    , mDataCopied{std::make_unique<uint8_t[]>(size)}
    , mDataSize{size}
{
    assert(mDataCopied);
    assert(mDataSize > 0);
}

ByteArray::ByteArray( //
    std::unique_ptr<uint8_t[]> &&ptr,
    const uint32_t size)
    : mMode{Mode::kCopy}
    , mDataRaw{nullptr}
    , mDataCopied{std::move(ptr)}
    , mDataSize{size}
{
    assert(mDataCopied);
    assert(mDataSize > 0);
}

utils::ByteArray::ByteArray( //
    uint8_t *const newData,
    const uint32_t newSize,
    const Mode mode)
    : mMode{mode}
    , mDataRaw{nullptr}
    , mDataCopied{}
    , mDataSize{newSize}
{
    assert(newData != nullptr);
    assert(newSize > 0);

    if (mMode == Mode::kCopy)
    {
        mDataCopied = std::make_unique<uint8_t[]>(newSize);
        memcpy(mDataCopied.get(), newData, newSize);
    }
    else if (mMode == Mode::kNoCopy)
    {
        mDataRaw = newData;
    }
    else
    {
        assert(nullptr == "invalid byte array mode");
    }
}

ByteArray::ByteArray( //
    char *const newData,
    const uint32_t newSize,
    const ByteArray::Mode mode)
    : ByteArray{(uint8_t *)newData, newSize, mode}
{
}

// const casting here, assuming user knows what he's doing
ByteArray::ByteArray( //
    const char *const newData,
    const unsigned long newSize,
    const ByteArray::Mode mode)
    : ByteArray{(uint8_t *)newData, (uint32_t)newSize, mode}
{
}

uint8_t *utils::ByteArray::ptr() const
{
    if (mMode == Mode::kCopy)
    {
        assert(mDataCopied);
        return mDataCopied.get();
    }
    else if (mMode == Mode::kNoCopy)
    {
        assert(mDataRaw != nullptr);
        return mDataRaw;
    }
    else
    {
        assert(nullptr == "invalid byte array mode");
    }

    return nullptr;
}

uint32_t utils::ByteArray::size() const
{
    return mDataSize;
}

utils::ByteArray::operator void *() const
{
    return (void *)ptr();
}

utils::ByteArray::operator char *() const
{
    return (char *)ptr();
}

utils::ByteArray::operator size_t() const
{
    return (size_t)size();
}

} // namespace utils
