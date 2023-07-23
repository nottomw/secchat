#include "Crypto.hpp"

#include <cassert>
#include <cstring>
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

utils::ByteArray symEncryptGetNonce()
{
    utils::ByteArray ba;

    ba.data =                       //
        std::unique_ptr<uint8_t[]>( //
            new uint8_t[crypto_secretbox_NONCEBYTES]);
    ba.dataSize = crypto_secretbox_NONCEBYTES;

    randombytes_buf(ba.data.get(), crypto_secretbox_NONCEBYTES);

    return ba;
}

EncryptedData symEncrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const utils::ByteArray &nonce)
{
    EncryptedData res;

    res.nonce =                     //
        std::unique_ptr<uint8_t[]>( //
            new uint8_t[crypto_secretbox_NONCEBYTES]);
    res.nonceSize = crypto_secretbox_NONCEBYTES;

    // unnecessary copy?
    memcpy(res.nonce.get(), nonce.data.get(), crypto_secretbox_NONCEBYTES);

    res.data =                      //
        std::unique_ptr<uint8_t[]>( //
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

std::optional<DecryptedData> symDecrypt( //
    const KeySym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize,
    const utils::ByteArray &nonce)
{
    DecryptedData decryptedData;

    assert(nonce.dataSize == crypto_secretbox_NONCEBYTES);

    const uint32_t plaintextSize = bufferSize - crypto_secretbox_MACBYTES;

    decryptedData.data =            //
        std::unique_ptr<uint8_t[]>( //
            new uint8_t[plaintextSize]);
    decryptedData.dataSize = plaintextSize;

    const int openOk = crypto_secretbox_open_easy( //
        decryptedData.data.get(),
        buffer,
        bufferSize,
        nonce.data.get(),
        key.mKey);
    if (openOk != 0)
    {
        return std::nullopt;
    }

    return decryptedData;
}

EncryptedData asymEncrypt( //
    const KeyAsym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    const uint32_t encryptedDataSize = crypto_box_SEALBYTES + bufferSize;

    EncryptedData data;

    data.data = std::unique_ptr<uint8_t[]>( //
        new uint8_t[encryptedDataSize]);
    data.dataSize = encryptedDataSize;

    const int encryptOk =                //
        crypto_box_seal(data.data.get(), //
                        buffer,
                        bufferSize,
                        key.mKeyPub);
    assert(encryptOk == 0);

    return data;
}

DecryptedData asymDecrypt( //
    const KeyAsym &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    const uint32_t decryptedDataSize = bufferSize - crypto_box_SEALBYTES;

    DecryptedData data;
    data.data = std::unique_ptr<uint8_t[]>( //
        new uint8_t[decryptedDataSize]);
    data.dataSize = decryptedDataSize;

    const int decryptOk =     //
        crypto_box_seal_open( //
            data.data.get(),
            buffer,
            bufferSize,
            key.mKeyPub,
            key.mKeyPriv);
    assert(decryptOk == 0);

    return data;
}

SignedData sign( //
    const KeyAsymSignature &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    SignedData signedData;

    const uint32_t signedDataSize = bufferSize + crypto_sign_BYTES;
    signedData.dataSize = signedDataSize;

    signedData.data = std::unique_ptr<uint8_t[]>( //
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

std::optional<NonsignedData> signedVerify( //
    const KeyAsymSignature &key,
    const uint8_t *const buffer,
    const uint32_t bufferSize)
{
    NonsignedData nonsignedData;
    nonsignedData.data = std::unique_ptr<uint8_t[]>( //
        new uint8_t[bufferSize]);
    nonsignedData.dataSize = 0U; // updated later

    unsigned long long nonsignedDataSize = 0U;
    const int signatureOk = //
        crypto_sign_open(   //
            nonsignedData.data.get(),
            &nonsignedDataSize,
            buffer,
            bufferSize,
            key.mKeyPub);
    if (signatureOk != 0)
    {
        // verification failed
        return std::nullopt;
    }

    nonsignedData.dataSize = nonsignedDataSize;

    return nonsignedData;
}

KeyAsym::KeyAsym(const KeyAsym &k)
{
    copy(k);
}

KeyAsym &KeyAsym::operator=(const KeyAsym &k)
{
    copy(k);
    return *this;
}

void KeyAsym::copy(const KeyAsym &k)
{
    memcpy(mKeyPub, k.mKeyPub, kPubKeyByteCount);
    memcpy(mKeyPriv, k.mKeyPriv, kPrivKeyByteCount);
}

EncryptedData signAndEncrypt(const uint8_t *const data,
                             const uint32_t dataSize,
                             const KeyAsymSignature &sig,
                             const KeyAsym &encrypt)
{
    crypto::SignedData signedData = //
        crypto::sign(               //
            sig,
            data,
            dataSize);

    crypto::EncryptedData encryptedData = //
        crypto::asymEncrypt(encrypt,      //
                            signedData.data.get(),
                            signedData.dataSize);

    return encryptedData;
}

EncryptedData signAndEncrypt( //
    const utils::ByteArray &ba,
    const KeyAsymSignature &sig,
    const KeyAsym &encrypt)
{
    return signAndEncrypt(ba.ptr(), ba.size(), sig, encrypt);
}

std::optional<NonsignedData> decryptAndSignVerify( //
    const uint8_t *const data,
    const uint32_t dataSize,
    const KeyAsymSignature &sig,
    const KeyAsym &encrypt)
{
    auto decrypted = crypto::asymDecrypt( //
        encrypt,
        data,
        dataSize);

    auto nonsignedData = crypto::signedVerify( //
        sig,
        decrypted.data.get(),
        decrypted.dataSize);

    return nonsignedData;
}

std::optional<NonsignedData> decryptAndSignVerify(const char *const data,
                                                  const uint32_t dataSize,
                                                  const KeyAsymSignature &sig,
                                                  const KeyAsym &encrypt)
{
    return decryptAndSignVerify((uint8_t *)data, dataSize, sig, encrypt);
}

} // namespace crypto
