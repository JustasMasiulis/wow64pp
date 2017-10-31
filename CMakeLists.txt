cmake_minimum_required(VERSION 3.3)
project(wow64pp)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories (${PROJECT_SOURCE_DIR}/include)
add_library (wow64pp INTERFACE)
target_include_directories (wow64pp INTERFACE ${PROJECT_SOURCE_DIR}/include)
target_sources (wow64pp INTERFACE ${PROJECT_SOURCE_DIR}/include/wow64pp.hpp)

enable_testing()
add_subdirectory (test)
