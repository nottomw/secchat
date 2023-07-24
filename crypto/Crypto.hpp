#pragma once

#include "Utils.hpp"

#include <cstdint>
#include <memory>
#include <optional>

namespace crypto
{

static constexpr uint32_t kPubKeyByteCount = 32U;
static constexpr uint32_t kPrivKeyByteCount = 32U;
static constexpr uint32_t kSymKeyByteCount = 32U;

static constexpr uint32_t kPubKeySignatureByteCount = 32U;
static constexpr uint32_t kPrivKeySignatureByteCount = 64U;

struct KeyAsym
{
    KeyAsym() = default;
    KeyAsym(const KeyAsym &k);
    KeyAsym &operator=(const KeyAsym &k);
    KeyAsym(KeyAsym &&k);
    KeyAsym &operator=(KeyAsym &&k);

    ~KeyAsym() = default;

    uint8_t mKeyPub[kPubKeyByteCount];
    uint8_t mKeyPriv[kPrivKeyByteCount];

private:
    void copy(const KeyAsym &k);
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
    utils::ByteArray data;
    utils::ByteArray nonce; // not used in asymmetric encryption
};

using DecryptedData = utils::ByteArray;
using SignedData = utils::ByteArray;
using NonsignedData = utils::ByteArray; // strange name

bool init();

// Generate asym keys for encryption
KeyAsym keygenAsym();

// Generate asym keys for signatures
KeyAsymSignature keygenAsymSign();

KeySym keygenSym();

KeySym derive( //
    const KeySym &key,
    const utils::ByteArray &context,
    const utils::ByteArray &salt);

utils::ByteArray symEncryptGetNonce();

EncryptedData symEncrypt( //
    const KeySym &key,
    const utils::ByteArray &data,
    const utils::ByteArray &nonce);

std::optional<DecryptedData> symDecrypt( //
    const KeySym &key,
    const utils::ByteArray &data,
    const utils::ByteArray &nonce);

EncryptedData asymEncrypt( //
    const KeyAsym &key,
    const utils::ByteArray &data);

DecryptedData asymDecrypt( //
    const KeyAsym &key,
    const utils::ByteArray &data);

SignedData sign( //
    const KeyAsymSignature &key,
    const utils::ByteArray &data);

std::optional<NonsignedData> signedVerify( //
    const KeyAsymSignature &key,
    const utils::ByteArray &data);

EncryptedData signAndEncrypt( //
    const utils::ByteArray &ba,
    const KeyAsymSignature &sig,
    const KeyAsym &encrypt);

std::optional<NonsignedData> decryptAndSignVerify( //
    const utils::ByteArray &data,
    const KeyAsymSignature &sig,
    const KeyAsym &encrypt);

} // namespace crypto
