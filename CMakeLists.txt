# https://github.com/hedgewars/hw/blob/master/hedgewars/CMakeLists.txt 
cmake_minimum_required(VERSION 3.12)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules")
enable_language(Pascal)

set(CMAKE_Pascal_COMPILER_ARG1 "${CMAKE_Pascal_COMPILER_ARG1} -Mobjfpc")
set(CMAKE_Pascal_LINK_FLAGS "-Fl/usr/local/lib")

project(NaClTest Pascal)

add_executable(${PROJECT_NAME} 
    yProcs.pas 
    libSodium.pas
    NaClTest.pas)
