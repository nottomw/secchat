# External third-party libraries fetched with conan.

include_guard(GLOBAL)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
   message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
   file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/0.18.1/conan.cmake"
                 "${CMAKE_BINARY_DIR}/conan.cmake"
                 TLS_VERIFY ON)
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

# sodium - crypto
# asio - network
# protobuf - serdes
set(REQUIRED_LIBS libsodium/1.0.18 asio/1.28.0 protobuf/3.21.9)

# ncurses - terminal user interface
if ("${SECCHAT_MODE}" STREQUAL "ncurses")
    set(REQUIRED_LIBS ${REQUIRED_LIBS} ncurses/6.4)
endif()

conan_cmake_configure(
    REQUIRES ${REQUIRED_LIBS}
    GENERATORS cmake_find_package
)

conan_cmake_autodetect(settings)

conan_cmake_install(PATH_OR_REFERENCE .
                    BUILD missing
                    REMOTE conancenter
                    SETTINGS ${settings})

find_package(asio REQUIRED)
find_package(Curses REQUIRED)
find_package(libsodium REQUIRED)
find_package(Protobuf REQUIRED)
