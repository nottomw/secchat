#pragma once

class Crypto
{
public:
    struct KeyAsym
    {
    };

    struct KeySym
    {
    };

    bool init() const;

    KeyAsym keygen();
    KeySym derive(const KeySym &key);

    bool sym() const;
    bool asym() const;
};
