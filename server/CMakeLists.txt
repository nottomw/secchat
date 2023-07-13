# SecchatServer.

add_executable(SecchatServer
    ServerMain.cpp
    SecchatServer.cpp
)

target_link_libraries(SecchatServer
    PRIVATE
        secchat::crypto
        secchat::data_transport
        secchat::proto
)
