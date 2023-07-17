#include "Crypto.hpp"

#include <cassert>
#include <memory>
#include <sodium.h>

namespace crypto
{

static_assert(crypto_box_PUBLICKEYBYTES == kPubKeyByteCount);
static_assert(crypto_box_SECRETKEYBYTES == kPrivKeyByteCount);
static_assert(crypto_secretbox_KEYBYTES == kSymKeyByteCount);

static_assert(crypto_sign_PUBLICKEYBYTES == kPubKeySignatureByteCount);
static_assert(crypto_sign_SECRETKEYBYTES == kPrivKeySignatureByteCount);

bool init()
{
    if (sodium_init() < 0)
    {
        return false;
    }

    return true;
}

KeyAsym keygenAsym()
{
    KeyAsym key;

    const int keygenOk = crypto_box_keypair(key.mKeyPub, key.mKeyPriv);
    assert(keygenOk >= 0);

    return key;
}

KeyAsymSignature keygenAsymSign()
{
    KeyAsymSignature key;

    crypto_sign_keypair(key.mKeyPub, key.mKeyPriv);

    return key;
}

KeySym keygenSym()
{
    KeySym key;

    randombytes_buf(key.mKey, crypto_secretbox_KEYBYTES);

    return key;
}

KeySym derive(const KeySym &key,
              const uint8_t *const context,
              const uint32_t contextSize,
              const uint8_t *const salt,
              const uint32_t saltSize)
{
    KeySym derivedKey;

    static_assert(kSymKeyByteCount == crypto_secretstream_xchacha20poly1305_KEYBYTES);

    assert(salt[saltSize - 1] == '\0');
    assert(context[contextSize - 1] == '\0');

    const uint32_t subkeyId = 0U;
    const int deriveOk =            //
        crypto_kdf_derive_from_key( //
            derivedKey.mKey,
            kSymKeyByteCount,
            subkeyId,
            (char *)context,
            key.mKey);
    assert(deriveOk == 0);

    return derivedKey;
}

EncryptedData symEncrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    EncryptedData res;

    res.nonce =                     //
        std::shared_ptr<uint8_t[]>( //
            new uint8_t[crypto_secretbox_NONCEBYTES]);
    res.nonceSize = crypto_secretbox_NONCEBYTES;

    randombytes_buf(res.nonce.get(), crypto_secretbox_NONCEBYTES);

    res.data =                      //
        std::shared_ptr<uint8_t[]>( //
            new uint8_t[crypto_secretbox_MACBYTES + bufferSize]);
    res.dataSize = crypto_secretbox_MACBYTES + bufferSize;

    const int encryptionRes =  //
        crypto_secretbox_easy( //
            res.data.get(),
            buffer,
            bufferSize,
            res.nonce.get(),
            key.mKey);

    assert(encryptionRes == 0);

    return res;
}

DecryptedData symDecrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const uint8_t *const nonce,
    const uint32_t nonceSize)
{
    DecryptedData decryptedData;

    assert(nonceSize == crypto_secretbox_NONCEBYTES);

    const uint32_t plaintextSize = bufferSize - crypto_secretbox_MACBYTES;

    decryptedData.data =            //
        std::shared_ptr<uint8_t[]>( //
            new uint8_t[plaintextSize]);
    decryptedData.dataSize = plaintextSize;

    const int openOk = crypto_secretbox_open_easy( //
        decryptedData.data.get(),
        buffer,
        bufferSize,
        nonce,
        key.mKey);
    assert(openOk == 0);

    return decryptedData;
}

SignedData sign( //
    const KeyAsymSignature &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    SignedData signedData;

    const uint32_t signedDataSize = bufferSize + crypto_sign_BYTES;
    signedData.dataSize = signedDataSize;

    signedData.data = std::shared_ptr<uint8_t[]>( //
        new uint8_t[signedDataSize]);

    unsigned long long signedMessageLen = 0U;
    const int signOk = //
        crypto_sign(   //
            signedData.data.get(),
            &signedMessageLen,
            buffer,
            bufferSize,
            key.mKeyPriv);
    assert(signOk == 0);
    assert(signedMessageLen == (unsigned long long)signedDataSize);

    return signedData;
}

} // namespace crypto
