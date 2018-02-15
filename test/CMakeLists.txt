set (CATCH_MODULE_PATH "${PROJECT_SOURCE_DIR}/test/Catch")
set (CATCH_INCLUDE_PATH "${CATCH_MODULE_PATH}/include")

#include custom cmake function
include ("${CATCH_MODULE_PATH}/contrib/ParseAndAddCatchTests.cmake")

#configure variables
set (TEST_APP_NAME "wow64pp_test")

#configure directories
set (TEST_MODULE_PATH "${PROJECT_SOURCE_DIR}/test")

#set includes
include_directories (${PROJECT_SOURCE_DIR}/include ${CATCH_INCLUDE_PATH})

#set test sources
#file (GLOB TEST_SOURCE_FILES "$${CMAKE_CURRENT_LIST_DIR}/*.cpp")

set (TEST_SOURCE_FILES
        ${TEST_MODULE_PATH}/main.cpp)

#set target executable
add_executable (${TEST_APP_NAME} ${TEST_SOURCE_FILES})

#add the library
target_link_libraries (${TEST_APP_NAME} wow64pp)

# Turn on CMake testing capabilities
enable_testing()

#parse catch tests
ParseAndAddCatchTests (${TEST_APP_NAME})