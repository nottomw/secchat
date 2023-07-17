#pragma once

#include <cstdint>
#include <memory>

namespace crypto
{

static constexpr uint32_t kPubKeyByteCount = 32U;
static constexpr uint32_t kPrivKeyByteCount = 32U;
static constexpr uint32_t kSymKeyByteCount = 32U;

static constexpr uint32_t kPubKeySignatureByteCount = 32U;
static constexpr uint32_t kPrivKeySignatureByteCount = 64U;

struct KeyAsym
{
    uint8_t mKeyPub[kPubKeyByteCount];
    uint8_t mKeyPriv[kPrivKeyByteCount];
};

struct KeyAsymSignature
{
    uint8_t mKeyPub[kPubKeySignatureByteCount];
    uint8_t mKeyPriv[kPrivKeySignatureByteCount];
};

struct KeySym
{
    uint8_t mKey[kSymKeyByteCount];
};

struct EncryptedData
{
    std::shared_ptr<uint8_t[]> data;
    uint32_t dataSize;

    // not used in asymmetric encryption
    std::shared_ptr<uint8_t[]> nonce;
    uint32_t nonceSize;
};

struct DecryptedData
{
    std::shared_ptr<uint8_t[]> data;
    uint32_t dataSize;
};

using SignedData = DecryptedData;

bool init();

// Generate asym keys for encryption
KeyAsym keygenAsym();

// Generate asym keys for signatures
KeyAsymSignature keygenAsymSign();

KeySym keygenSym();

KeySym derive(const KeySym &key,
              const uint8_t *const context,
              const uint32_t contextSize,
              const uint8_t *const salt,
              const uint32_t saltSize);

EncryptedData symEncrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

DecryptedData symDecrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const uint8_t *const nonce,
    const uint32_t nonceSize);

EncryptedData asymEncrypt( //
    const KeyAsym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

DecryptedData asymDecrypt( //
    const KeyAsym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

SignedData asymSign( //
    const KeyAsymSignature &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize);

} // namespace crypto
