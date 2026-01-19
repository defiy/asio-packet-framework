# CMakeList.txt : CMake project for Everything, include source and define
# project specific logic here.
#

#####################################################
# Just a way to make a resource directory	        #
# Not sure if it's the proper way			        #
# But none of the other ways i tried worked	for WSL #
#####################################################

set(RESOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/*")
file(GLOB RESOURCE_FILES "${RESOURCE_DIR}")

#message(STATUS "RESOURCE_DIR ------> ${RESOURCE_DIR}")

set(TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/${resource}")

#message(STATUS "CMAKE_CURRENT_BINARY_DIR ------> ${CMAKE_CURRENT_BINARY_DIR}")

# Create the directory if it doesn't exist
file(MAKE_DIRECTORY ${TARGET_DIR})

foreach(_RESOURCE ${RESOURCE_FILES})
    configure_file(${_RESOURCE} "${CMAKE_CURRENT_BINARY_DIR}" COPYONLY)
    #message(STATUS "_RESOURCE ------> ${_RESOURCE}")
endforeach()


# TODO: Add tests and install targets if needed.
