# https://github.com/hedgewars/hw/blob/master/hedgewars/CMakeLists.txt 
cmake_minimum_required(VERSION 3.12)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules")

enable_language(Pascal)


project(NaClTest Pascal)cd cmake_minimum_required

add_executable(${PROJECT_NAME} yProcs.pas NaClTest.pas)
