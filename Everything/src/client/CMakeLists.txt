# CMakeList.txt : CMake project for Everything, include source and define
# project specific logic here.
#

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")

project ("client")

file(GLOB_RECURSE SOURCE_FILES "${CMAKE_SOURCE_DIR}/src/common/*.c*")
include_directories(${PROJECT_NAME} SHARED ${SOURCE_FILES})

include_directories(../../include)
include_directories(../common)

# Add source to this project's executable.
add_executable (client "client.cpp" "ssl_client.cpp" ${SOURCE_FILES})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET client PROPERTY CXX_STANDARD 20)
endif()

target_compile_definitions(client PRIVATE _CLIENT)

target_link_libraries(client
    ${CMAKE_SOURCE_DIR}/include/bin/win/libssl.lib
    ${CMAKE_SOURCE_DIR}/include/bin/win/libcrypto.lib
    Crypt32
)

add_subdirectory(resource)

endif()

# TODO: Add tests and install targets if needed.
