# Data transport.

add_library(data_transport
    DataTransport.cpp
)

target_include_directories(data_transport
    PUBLIC
        ${PROJECT_SOURCE_DIR}/data_transport
)

add_library(secchat::data_transport ALIAS data_transport)
