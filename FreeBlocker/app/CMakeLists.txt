cmake_minimum_required(VERSION 3.22.1)
project("freeblocker_rust_jni")

set(RUST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../free_block_rust")

if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(RUST_TARGET "aarch64-linux-android")
elseif(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(RUST_TARGET "armv7-linux-androideabi")
elseif(${ANDROID_ABI} STREQUAL "x86_64")
    set(RUST_TARGET "x86_64-linux-android")
elseif(${ANDROID_ABI} STREQUAL "x86")
    set(RUST_TARGET "i686-linux-android")
else()
    message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
endif()

set(RUST_SO_FILE "${RUST_DIR}/target/${RUST_TARGET}/release/libfree_block_rust.so")

add_custom_target(cargo_build_always ALL
    COMMAND ${CMAKE_COMMAND} -E env ANDROID_NDK_HOME=${CMAKE_ANDROID_NDK} PATH=$ENV{PATH}:/home/me/.cargo/bin cargo ndk -t ${ANDROID_ABI} build --release
    WORKING_DIRECTORY ${RUST_DIR}
    COMMENT "Building Rust library for ABI ${ANDROID_ABI}"
)

# Dummy command to satisfy IMPORTED_LOCATION requirement if needed
add_custom_command(
    OUTPUT ${RUST_SO_FILE}
    DEPENDS cargo_build_always
    COMMAND ${CMAKE_COMMAND} -E touch ${RUST_SO_FILE}
)

add_custom_target(cargo_build ALL DEPENDS ${RUST_SO_FILE})

add_library(free_block_rust SHARED IMPORTED)
set_target_properties(free_block_rust PROPERTIES IMPORTED_LOCATION ${RUST_SO_FILE})

add_library(dummy SHARED dummy.cpp)
target_link_libraries(dummy free_block_rust)
add_dependencies(dummy cargo_build)
