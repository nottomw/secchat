# Proto generated.

file(GLOB PROTO_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.proto")

add_library(proto_generated)

protobuf_generate(
    TARGET proto_generated
    LANGUAGE cpp
    PROTOS ${PROTO_FILES}
)

target_link_libraries(proto_generated
    PUBLIC
        protobuf::protobuf
)

target_include_directories(proto_generated
    PUBLIC
        # for some reason not added with protobuf_generate() target...
        ${CMAKE_CURRENT_BINARY_DIR}
)

add_library(secchat::proto_generated ALIAS proto_generated)
