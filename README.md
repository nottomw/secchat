## Secchat

![secchat ncurses](https://github.com/nottomw/secchat/actions/workflows/secchat-ncurses.yml/badge.svg)
![secchat terminal](https://github.com/nottomw/secchat/actions/workflows/secchat-terminal.yml/badge.svg)

### Info
Fun with crypto and networking.

Currently used:
- net: Asio (not boost::asio)
- crypto: libsodium
- UI: ncurses ( ;) )

### Build
```
$ mkdir build
$ cd build
$ cmake -G Ninja -S ../src/
$ ninja
```
