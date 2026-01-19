# CMakeList.txt : CMake project for Everything, include source and define
# project specific logic here.
#

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")

project ("server")

# Add source to this project's executable.

file(GLOB_RECURSE SOURCE_FILES "${CMAKE_SOURCE_DIR}/src/common/*.c*")
include_directories(${PROJECT_NAME} SHARED ${SOURCE_FILES})

add_executable (server "server.cpp" "ssl_session.cpp" "ssl_server.cpp" ${SOURCE_FILES})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET server PROPERTY CXX_STANDARD 20)
endif()

target_compile_definitions(server PRIVATE _SERVER)

include_directories(../../include)
include_directories(../common)

target_link_libraries(server ${CMAKE_SOURCE_DIR}/include/bin/unix/libssl.a)
target_link_libraries(server ${CMAKE_SOURCE_DIR}/include/bin/unix/libcrypto.a)

add_subdirectory(resource)

endif()

# TODO: Add tests and install targets if needed.
