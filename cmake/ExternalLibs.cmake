# External third-party libraries fetched with conan.

include_guard(GLOBAL)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
   message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
   file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/master/conan.cmake"
                  "${CMAKE_BINARY_DIR}/conan.cmake")
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

# cryptography
conan_cmake_run(REQUIRES libsodium/1.0.18
                BUILD missing
                BASIC_SETUP CMAKE_TARGETS)

# networking
conan_cmake_run(REQUIRES asio/1.28.0
                BUILD missing
                BASIC_SETUP CMAKE_TARGETS)
