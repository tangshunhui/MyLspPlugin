project(plugin)
cmake_minimum_required(VERSION 3.4.1)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)  # 或者根据需要设置为 20

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
# target_include_directories(${PROJECT_NAME} PUBLIC include)

aux_source_directory(. SRC_LIST)
add_library(pg SHARED ${SRC_LIST})


find_library(log-lib log)
target_link_libraries(pg ${log-lib})
