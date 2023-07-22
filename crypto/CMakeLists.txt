# Crypto.

add_library(crypto
    Crypto.cpp
)

target_include_directories(crypto
    PUBLIC
        ${PROJECT_SOURCE_DIR}/crypto
)

target_link_libraries(crypto
    PRIVATE
        libsodium::libsodium
        secchat::utils
)

add_library(secchat::crypto ALIAS crypto)
