# Secchat

![secchat ncurses](https://github.com/nottomw/secchat/actions/workflows/secchat-ncurses.yml/badge.svg)
![secchat terminal](https://github.com/nottomw/secchat/actions/workflows/secchat-terminal.yml/badge.svg)

## Info
Fun with crypto and networking - e2e encrypted chat.

Currently used libs:
- net: `Asio` (not boost::asio)
- crypto: `libsodium`
- serdes: `protobuf`
- UI: `ncurses` ( ;) )

Packages fetched by `cmake` with `conan`.

## Build
```
$ mkdir build
$ cd build
$ cmake -G Ninja -S ../src/ -DSECCHAT_MODE=ncurses
$ ninja
```
