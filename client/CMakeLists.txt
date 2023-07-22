# SecchatClient.

if ("${SECCHAT_MODE}" STREQUAL "ncurses")

    set(LIB_NCURSES ncurses::ncurses)
    set(USER_INTERFACES_SOURCES ui_ncurses/UserInterface.cpp)

elseif("${SECCHAT_MODE}" STREQUAL "terminal")

    set(USER_INTERFACES_SOURCES ui_terminal/UserInterface.cpp)

endif()

add_executable(SecchatClient
    ClientMain.cpp
    SecchatClient.cpp
    ${USER_INTERFACES_SOURCES}
)

target_link_libraries(SecchatClient
    PRIVATE
        secchat::utils
        secchat::crypto
        secchat::data_transport
        secchat::proto

        ${LIB_NCURSES}
)

target_include_directories(SecchatClient
    PUBLIC
        ${PROJECT_SOURCE_DIR}/client
)
