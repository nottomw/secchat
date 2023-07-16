#include "Crypto.hpp"

#include <cassert>
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

KeySym derive(const KeySym &key)
{
    // TODO: derive implement

    return key;
}

} // namespace crypto
