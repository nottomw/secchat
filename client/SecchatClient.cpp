#include "Crypto.hpp"

#include <cstdio>

int main(int argc, char **argv)
{
    Crypto crypto;
    if (!crypto.init())
    {
        printf("Crypto init failed\n");
    }

    printf("Hello world from client...\n");

    return 0;
}
