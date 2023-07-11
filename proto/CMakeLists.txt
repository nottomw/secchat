# Proto.

add_library(proto
    Proto.cpp
)

target_include_directories(proto
    PUBLIC
        ${PROJECT_SOURCE_DIR}/proto
)

add_library(secchat::proto ALIAS proto)
