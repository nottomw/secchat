# Utils

add_library(utils
    Utils.cpp
    WaitQueue.cpp
    ByteArray.cpp
)

target_include_directories(utils
    PUBLIC
        ${PROJECT_SOURCE_DIR}/utils
)

add_library(secchat::utils ALIAS utils)
