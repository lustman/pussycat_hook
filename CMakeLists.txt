cmake_minimum_required(VERSION 3.31)
project(pussycat_hook)
set(CMAKE_CXX_STANDARD 23)


include(FetchContent)
FetchContent_Declare(
        minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG master
)
FetchContent_MakeAvailable(minhook)


add_library(pussycat_hook SHARED
        src/entry.cpp
        src/scanner/scan.cpp
        src/scanner/scan.hpp
)


target_link_libraries(pussycat_hook PRIVATE minhook)