## Secchat

![secchat ncurses](https://github.com/nottomw/secchat/actions/workflows/cmake.yml/badge.svg)

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

### Config
There is a possibility to build only with terminal (printfs-like),
to disable ncurses in main CMakeLists.txt change:

```
secchat_mode_set(ncurses)
```

to:

```
secchat_mode_set(terminal)
```
