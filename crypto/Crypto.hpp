#pragma once

#include <cstdint>
#include <memory>

namespace crypto
{

static constexpr uint32_t kPubKeyByteCount = 32U;
static constexpr uint32_t kPrivKeyByteCount = 32U;
static constexpr uint32_t kSymKeyByteCount = 32U;

struct KeyAsym
{
    uint8_t mKeyPub[kPubKeyByteCount];
    uint8_t mKeyPriv[kPrivKeyByteCount];
};

struct KeySym
{
    uint8_t mKey[kSymKeyByteCount];
};

bool init();

KeyAsym keygenAsym();

KeySym keygenSym();

KeySym derive(const KeySym &key);

bool symEncrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

std::shared_ptr<uint8_t[]> symDecrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

bool asymEncrypt( //
    const KeyAsym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

std::shared_ptr<uint8_t[]> asymDecrypt( //
    const KeyAsym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

} // namespace crypto
