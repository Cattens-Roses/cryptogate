cmake_minimum_required(VERSION 3.16)
project(ltcengine VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

# Keep shared-lib next to the binary on Linux/macOS (WSL-friendly).
if(UNIX)
  set(CMAKE_BUILD_RPATH_USE_ORIGIN ON)
endif()

include(FetchContent)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
# Static secp on Linux/WSL avoids soname symlink issues on /mnt/c (drvfs).
if(UNIX)
  set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "" FORCE)
endif()
FetchContent_Declare(
  secp256k1
  GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
  GIT_TAG        v0.5.1
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(secp256k1)

find_package(Threads REQUIRED)

add_library(ltc_core STATIC
  src/crypto/hash.cpp
  src/crypto/base58.cpp
  src/crypto/bech32.cpp
  src/crypto/aes.cpp
  src/wallet/bip39.cpp
  src/wallet/hd.cpp
  src/wallet/script.cpp
  src/wallet/transaction.cpp
  src/wallet/wallet.cpp
  src/net/serialize.cpp
  src/net/bloom.cpp
  src/net/peer.cpp
  src/net/spv.cpp
  src/util/fs.cpp
  src/util/error_log.cpp
)

target_include_directories(ltc_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${secp256k1_SOURCE_DIR}/include
)

target_link_libraries(ltc_core PUBLIC secp256k1 Threads::Threads)

if(WIN32)
  target_link_libraries(ltc_core PUBLIC ws2_32 crypt32 bcrypt)
  target_compile_definitions(ltc_core PUBLIC _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

add_executable(ltcengine
  src/cli/main.cpp
  src/cli/tui.cpp
  src/cli/background_sync.cpp
)
target_link_libraries(ltcengine PRIVATE ltc_core)

if(UNIX)
  # $ORIGIN so bin/ltcengine finds libsecp256k1 next to itself.
  set_target_properties(ltcengine PROPERTIES
    BUILD_RPATH "$ORIGIN"
    INSTALL_RPATH "$ORIGIN"
  )
endif()

# Copy binary into ./bin for build.sh / build.bat.
# On Windows also copy the secp shared DLL; Linux links secp statically.
add_custom_command(TARGET ltcengine POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/bin
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:ltcengine>
    ${CMAKE_SOURCE_DIR}/bin/
  COMMENT "Copy ltcengine to bin/"
)
if(WIN32)
  add_custom_command(TARGET ltcengine POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:secp256k1>
      ${CMAKE_SOURCE_DIR}/bin/
    COMMENT "Copy libsecp256k1 DLL to bin/"
  )
endif()

install(TARGETS ltcengine RUNTIME DESTINATION bin)
