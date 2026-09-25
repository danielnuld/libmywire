cmake_minimum_required(VERSION 3.16)
project(libmywire VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(MW_WERROR "Treat warnings as errors" OFF)
option(MW_BUILD_TESTS "Build the tests" ON)

if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
  set(MW_WARN /W4)
  if(MW_WERROR)
    list(APPEND MW_WARN /WX)
  endif()
else()
  set(MW_WARN -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion)
  if(MW_WERROR)
    list(APPEND MW_WARN -Werror)
  endif()
endif()

# OpenSSL is not optional: both password plugins need SHA-1/SHA-256, and
# caching_sha2_password needs RSA or TLS.
find_package(OpenSSL 1.1.1 REQUIRED)

add_library(mywire STATIC src/proto.c src/mywire.c)
target_include_directories(mywire PUBLIC include PRIVATE src)
target_compile_options(mywire PRIVATE ${MW_WARN})
target_link_libraries(mywire PUBLIC OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(mywire PUBLIC ws2_32 crypt32)
  target_compile_definitions(mywire PRIVATE WIN32_LEAN_AND_MEAN)
endif()

if(MW_BUILD_TESTS)
  enable_testing()
  add_executable(test_proto tests/test_proto.c src/proto.c)
  target_include_directories(test_proto PRIVATE src)
  target_link_libraries(test_proto PRIVATE OpenSSL::Crypto)
  target_compile_options(test_proto PRIVATE ${MW_WARN})
  add_test(NAME proto COMMAND test_proto)

  # Runs against a live server when MW_TEST_HOST is set; skips otherwise.
  find_package(Threads REQUIRED)
  add_executable(test_live tests/test_live.c)
  target_link_libraries(test_live PRIVATE mywire Threads::Threads)
  target_compile_options(test_live PRIVATE ${MW_WARN})
  add_test(NAME live COMMAND test_live)
  set_tests_properties(live PROPERTIES SKIP_RETURN_CODE 77)
endif()
