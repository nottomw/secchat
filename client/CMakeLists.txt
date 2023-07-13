# SecchatClient.

add_executable(SecchatClient
    ClientMain.cpp
    SecchatClient.cpp
)

target_link_libraries(SecchatClient
    PRIVATE
        secchat::crypto
        secchat::data_transport
        secchat::proto
)
