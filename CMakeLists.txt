cmake_minimum_required(VERSION 3.15.0)
project(tls_test CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 17)

# Main source code
file(GLOB_RECURSE CPP_LIST src/*.cpp)
include_directories(src)

add_executable(tls_test ${CPP_LIST})

# brotli
find_package(unofficial-brotli CONFIG REQUIRED)
target_link_libraries(tls_test PRIVATE unofficial::brotli::brotlidec)

# boringssl (!!! not regular OpenSSL !!!)
find_package(OpenSSL REQUIRED)
target_link_libraries(tls_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# boost
find_package(Boost REQUIRED)
target_link_libraries(tls_test PRIVATE Boost::boost)
