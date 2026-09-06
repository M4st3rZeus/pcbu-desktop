cmake_minimum_required(VERSION 3.28)
project(pcbu_elevator)

set(CMAKE_CXX_STANDARD 20)

add_executable(pcbu_elevator
        src/main.cpp
)

# The GUI looks for the helper beside its own executable, so drop it into the
# app bundle's MacOS dir (or the plain output dir elsewhere).
if(APPLE)
    set_target_properties(pcbu_elevator PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/desktop/pcbu_desktop.app/Contents/MacOS")
else()
    set_target_properties(pcbu_elevator PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/desktop")
endif()
