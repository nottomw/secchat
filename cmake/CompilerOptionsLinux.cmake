# Compiler options for Linux platform

set(CMAKE_C_COMPILER gcc)
set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
#    set(VERBOSE ON)

    set(SANITIZERS_FLAGS -fsanitize=address -fsanitize=undefined)
    #set(SANITIZERS_FLAGS) # use when running under valgrind

    set(DEBUG_FLAGS -ggdb -O0 ${SANITIZERS_FLAGS} -Wno-unused-parameter)
    set(COMPILER_FLAGS ${DEBUG_FLAGS})
else()
    set(COMPILER_FLAGS -O3 -march=native)
endif()

add_compile_options(-Wall -Wextra -Werror -pedantic ${COMPILER_FLAGS})

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_link_options(${SANITIZERS_FLAGS})
endif()
