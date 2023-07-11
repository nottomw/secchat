cmake_minimum_required(VERSION 3.18)

project(secchat CXX C)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_BUILD_TYPE Release)

add_compile_options(-Wall -Wextra -pedantic)
add_compile_options(-O0 -g)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
   message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
   file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/master/conan.cmake"
                  "${CMAKE_BINARY_DIR}/conan.cmake")
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_run(REQUIRES libsodium/1.0.18
                BUILD missing
                BASIC_SETUP CMAKE_TARGETS)

add_subdirectory(crypto)
add_subdirectory(data_transport)
add_subdirectory(proto)
add_subdirectory(client)
add_subdirectory(server)
