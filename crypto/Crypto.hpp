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

struct SymEncryptedData
{
    std::shared_ptr<uint8_t[]> data;
    uint32_t dataSize;

    std::shared_ptr<uint8_t[]> nonce;
    uint32_t nonceSize;
};

struct SymDecryptedData
{
    std::shared_ptr<uint8_t[]> data;
    uint32_t dataSize;
};

bool init();

KeyAsym keygenAsym();

KeySym keygenSym();

KeySym derive(const KeySym &key,
              const uint8_t *const context,
              const uint32_t contextSize,
              const uint8_t *const salt,
              const uint32_t saltSize);

SymEncryptedData symEncrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

SymDecryptedData symDecrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const uint8_t *const nonce,
    const uint32_t nonceSize);

std::shared_ptr<uint8_t[]> asymEncrypt( //
    const KeyAsym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

std::shared_ptr<uint8_t[]> asymDecrypt( //
    const KeyAsym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

} // namespace crypto
