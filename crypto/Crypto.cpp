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

KeySym derive( //
    const KeySym &key,
    const utils::ByteArray &context,
    const utils::ByteArray & /*salt*/)
{
    KeySym derivedKey;

    static_assert(kSymKeyByteCount == crypto_secretstream_xchacha20poly1305_KEYBYTES);

    const uint32_t subkeyId = 0U;
    const int deriveOk =            //
        crypto_kdf_derive_from_key( //
            derivedKey.mKey,
            kSymKeyByteCount,
            subkeyId,
            context,
            key.mKey);
    assert(deriveOk == 0);

    return derivedKey;
}

utils::ByteArray symEncryptGetNonce()
{
    utils::ByteArray ba{crypto_secretbox_NONCEBYTES};

    randombytes_buf(ba.ptr(), crypto_secretbox_NONCEBYTES);

    return ba;
}

EncryptedData symEncrypt( //
    const KeySym &key,
    const utils::ByteArray &data,
    const utils::ByteArray &nonce)
{
    EncryptedData res;
    res.nonce = utils::ByteArray{crypto_secretbox_NONCEBYTES};
    res.data = utils::ByteArray{crypto_secretbox_MACBYTES + data.size()};

    // maybe nonce could be std::moved instead of copied
    memcpy(res.nonce.ptr(), nonce.ptr(), crypto_secretbox_NONCEBYTES);

    const int encryptionRes =  //
        crypto_secretbox_easy( //
            res.data.ptr(),
            data.ptr(),
            data.size(),
            res.nonce.ptr(),
            key.mKey);
    assert(encryptionRes == 0);

    return res;
}

std::optional<DecryptedData> symDecrypt( //
    const KeySym &key,
    const utils::ByteArray &data,
    const utils::ByteArray &nonce)
{

    assert(nonce.size() == crypto_secretbox_NONCEBYTES);

    const uint32_t plaintextSize = data.size() - crypto_secretbox_MACBYTES;

    DecryptedData decryptedData{plaintextSize};

    const int openOk = crypto_secretbox_open_easy( //
        decryptedData.ptr(),
        data.ptr(),
        data.size(),
        nonce.ptr(),
        key.mKey);
    if (openOk != 0)
    {
        return std::nullopt;
    }

    return decryptedData;
}

EncryptedData asymEncrypt( //
    const KeyAsym &key,
    const utils::ByteArray &data)
{
    const uint32_t encryptedDataSize = crypto_box_SEALBYTES + data.size();

    EncryptedData encryptedData;
    encryptedData.data = utils::ByteArray{encryptedDataSize};

    const int encryptOk =                         //
        crypto_box_seal(encryptedData.data.ptr(), //
                        data.ptr(),
                        data.size(),
                        key.mKeyPub);
    assert(encryptOk == 0);

    return encryptedData;
}

DecryptedData asymDecrypt( //
    const KeyAsym &key,
    const utils::ByteArray &data)
{
    const uint32_t decryptedDataSize = data.size() - crypto_box_SEALBYTES;

    DecryptedData decryptedData{decryptedDataSize};

    const int decryptOk =     //
        crypto_box_seal_open( //
            decryptedData.ptr(),
            data.ptr(),
            data.size(),
            key.mKeyPub,
            key.mKeyPriv);
    assert(decryptOk == 0);

    return decryptedData;
}

SignedData sign( //
    const KeyAsymSignature &key,
    const utils::ByteArray &data)
{
    const uint32_t signedDataSize = data.size() + crypto_sign_BYTES;

    SignedData signedData{signedDataSize};

    unsigned long long signedMessageLen = 0U;
    const int signOk = //
        crypto_sign(   //
            signedData.ptr(),
            &signedMessageLen,
            data.ptr(),
            data.size(),
            key.mKeyPriv);
    assert(signOk == 0);
    assert(signedMessageLen == (unsigned long long)signedDataSize);

    return signedData;
}

std::optional<NonsignedData> signedVerify( //
    const KeyAsymSignature &key,
    const utils::ByteArray &data)
{
    // reserve more size, the internal NonsignedData size() is updated later
    auto buf = std::make_unique<uint8_t[]>(data.size());

    unsigned long long nonsignedDataSize = 0U;
    const int signatureOk = //
        crypto_sign_open(   //
            buf.get(),
            &nonsignedDataSize,
            data.ptr(),
            data.size(),
            key.mKeyPub);
    if (signatureOk != 0)
    {
        // signature verification failed
        return std::nullopt;
    }

    NonsignedData nonsignedData{std::move(buf), (uint32_t)nonsignedDataSize};

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

KeyAsym::KeyAsym(KeyAsym &&k)
{
    copy(k);
}

KeyAsym &KeyAsym::operator=(KeyAsym &&k)
{
    copy(k);
    return *this;
}

void KeyAsym::copy(const KeyAsym &k)
{
    memcpy(mKeyPub, k.mKeyPub, kPubKeyByteCount);
    memcpy(mKeyPriv, k.mKeyPriv, kPrivKeyByteCount);
}

EncryptedData signAndEncrypt( //
    const utils::ByteArray &ba,
    const KeyAsymSignature &sig,
    const KeyAsym &encrypt)
{
    crypto::SignedData signedData = crypto::sign(sig, ba);
    crypto::EncryptedData encryptedData = crypto::asymEncrypt(encrypt, signedData);

    return encryptedData;
}

std::optional<NonsignedData> decryptAndSignVerify( //
    const utils::ByteArray &data,
    const KeyAsymSignature &sig,
    const KeyAsym &encrypt)
{
    auto decrypted = crypto::asymDecrypt(encrypt, data);
    auto nonsignedData = crypto::signedVerify(sig, decrypted);

    return nonsignedData;
}

} // namespace crypto
