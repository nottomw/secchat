# Compiler options for Linux platform

set(CMAKE_C_COMPILER gcc)
set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

set(SANITIZERS_FLAGS -fsanitize=address -fsanitize=undefined)
#set(SANITIZERS_FLAGS)

set(DEBUG_FLAGS -ggdb -O0 ${SANITIZERS_FLAGS} -Wno-unused-parameter)

add_compile_options(-Wall -Wextra -Werror -pedantic ${DEBUG_FLAGS})

add_link_options(${SANITIZERS_FLAGS})
