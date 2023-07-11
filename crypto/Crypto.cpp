#include "Crypto.hpp"

#include <sodium.h>

bool Crypto::init() const
{
    if (sodium_init() < 0)
    {
        return false;
    }

    return true;
}
