cmake_minimum_required(VERSION 3.2)

project(findApi)

set(CMAKE_CXX_STANDARD 17)

file(GLOB SOURCES 
    ${CMAKE_SOURCE_DIR}/*.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

find_library(log-lib log)
target_link_libraries(${PROJECT_NAME} PRIVATE ${log-lib})

# LIEF
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third-party/LIEF)
target_link_libraries(${PROJECT_NAME} PRIVATE packLIEF)

# capstone
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third-party/capstone)
target_link_libraries(${PROJECT_NAME} PRIVATE packCapstone)

set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})