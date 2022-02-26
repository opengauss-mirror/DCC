aux_source_directory(. PROTOCOL_SRC)

# generate static library
add_library(zeprotocol OBJECT ${PROTOCOL_SRC})
