# Data transport.

add_library(data_transport
    DataTransport.cpp
    Session.cpp
)

target_include_directories(data_transport
    PUBLIC
        ${PROJECT_SOURCE_DIR}/data_transport
)

target_link_libraries(data_transport
   CONAN_PKG::asio
)

add_library(secchat::data_transport ALIAS data_transport)
