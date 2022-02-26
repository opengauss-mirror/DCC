aux_source_directory(. COMMON_SRC)
aux_source_directory(variant COMMON_VARIANT_SRC)

set(COMMON_ALL_SRC ${COMMON_VARIANT_SRC} ${COMMON_SRC})

# generate static library
add_library(zecommon OBJECT ${COMMON_ALL_SRC})