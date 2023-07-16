#include "Crypto.hpp"

#include <cassert>
#include <memory>
#include <sodium.h>

namespace crypto
{

static_assert(crypto_box_PUBLICKEYBYTES == crypto::kPubKeyByteCount);
static_assert(crypto_box_SECRETKEYBYTES == crypto::kPrivKeyByteCount);
static_assert(crypto_secretbox_KEYBYTES == crypto::kSymKeyByteCount);

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

SymEncryptedData symEncrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    SymEncryptedData res;

    res.nonce =                     //
        std::shared_ptr<uint8_t[]>( //
            new uint8_t[crypto_secretbox_MACBYTES + bufferSize]);
    res.nonceSize = crypto_secretbox_MACBYTES + bufferSize;

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

SymDecryptedData symDecrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const uint8_t *const nonce,
    const uint32_t nonceSize)
{
    SymDecryptedData decryptedData;

    assert(nonceSize == bufferSize);

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

} // namespace crypto
