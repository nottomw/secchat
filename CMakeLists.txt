cmake_minimum_required(VERSION 3.18)

project(secchat CXX C)

# This actually impacts only client, so maybe should be moved there?
include(${PROJECT_SOURCE_DIR}/cmake/SecchatModes.cmake)

secchat_mode_set(ncurses)
#secchat_mode_set(terminal)

include(${PROJECT_SOURCE_DIR}/cmake/CompilerOptionsLinux.cmake)
include(${PROJECT_SOURCE_DIR}/cmake/ExternalLibs.cmake)

add_subdirectory(utils)
add_subdirectory(crypto)
add_subdirectory(data_transport)
add_subdirectory(proto)
add_subdirectory(client)
add_subdirectory(server)
