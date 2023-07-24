#pragma once

#include <memory>
#include <cstdint>


namespace utils{

// Poor man's byte array for now...
// Similar to std::span<>.
class ByteArray
{
public:
    enum class Mode
    {
        kCopy,  // data is copied from source buffer
        kNoCopy // data not copied - pointer used internally
    };

    ByteArray() = default;
    ByteArray(const ByteArray &) = default;
    ByteArray(ByteArray &&) = default;
    ByteArray &operator=(const ByteArray &) = default;
    ByteArray &operator=(ByteArray &&) = default;

    ~ByteArray() = default;

    // Construct byte array and allocate internal ptr() with size
     ByteArray(const uint32_t size);

    // Construct byte array and consume ptr
     ByteArray(std::unique_ptr<uint8_t[]> &&ptr, const uint32_t size);

    // Construct byte array and either copy newData or assign internal
    // pointer (shallow copy)
      ByteArray(uint8_t *const newData, //
              const uint32_t newSize,
              const Mode mode = Mode::kCopy);

      ByteArray(char *const newData, //
              const uint32_t newSize,
              const Mode mode = Mode::kCopy);

      ByteArray(const char *const newData, //
              const unsigned long newSize,
              const Mode mode = Mode::kCopy);

    // add cast operators so it's a little easier to use
    // while passing as argument
    operator size_t() const;
    operator void *() const;
    operator char *() const;

    // Return internal pointer, if this is copy mode the pointer has the
    // exactly the same lifetime of byte array.
    uint8_t *ptr() const;

    uint32_t size() const;

private:
    Mode mMode;
    uint8_t *mDataRaw;
    std::unique_ptr<uint8_t[]> mDataCopied;
    uint32_t mDataSize;
};

}
