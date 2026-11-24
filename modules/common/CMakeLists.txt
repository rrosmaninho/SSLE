# Shared helpers: identity, registry client, logging, Prometheus formatting.
add_library(ssle_common STATIC src/ssle.cpp)
target_include_directories(ssle_common PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${HTTPLIB_INCLUDE_DIR})
target_link_libraries(ssle_common PUBLIC
  ${HTTPLIB_LIBRARY} nlohmann_json::nlohmann_json
  Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
