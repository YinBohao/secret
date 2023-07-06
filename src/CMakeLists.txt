cmake_minimum_required(VERSION 3.27.0-rc3)
PROJECT(the_first_book)


ADD_EXECUTABLE(out main.cpp)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g") 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g") 

# -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake
