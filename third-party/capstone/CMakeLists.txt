cmake_minimum_required(VERSION 3.5)

project(packCapstone)

add_library(${PROJECT_NAME} INTERFACE)

if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${ANDROID_ABI}/libcapstone.a)
    message("Extract capstone.7z to ${CMAKE_CURRENT_SOURCE_DIR}")
    execute_process(COMMAND 7z x ${CMAKE_CURRENT_SOURCE_DIR}/capstone.7z -o${CMAKE_CURRENT_SOURCE_DIR})
endif ()

target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${ANDROID_ABI}/libcapstone.a)