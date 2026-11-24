add_executable(ssle-storage src/main.cpp)
target_include_directories(ssle-storage PRIVATE ${SQLITE3_INCLUDE_DIR})
target_link_libraries(ssle-storage PRIVATE ssle_common ${SQLITE3_LIBRARY})
