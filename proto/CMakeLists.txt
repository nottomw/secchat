# Proto.

add_library(proto
    Proto.cpp
)

target_include_directories(proto
    PUBLIC
        ${PROJECT_SOURCE_DIR}/proto
)

target_link_libraries(proto
    PRIVATE
        secchat::crypto
        secchat::utils
)

add_library(secchat::proto ALIAS proto)
