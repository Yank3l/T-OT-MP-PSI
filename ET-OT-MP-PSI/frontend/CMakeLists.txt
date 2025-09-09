
#project(fronend)

find_library(GMP_LIB gmp)

if(GMP_LIB)
    message(STATUS "Found gmp library: ${GMP_LIB}")
else()
    message(WARNING "gmp library not found")
endif()
 

#############################################
#               Build fronend.exe           #
#############################################

file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/frontend/*.cpp  ${CMAKE_SOURCE_DIR}/frontend/utils/*.cpp  ${CMAKE_SOURCE_DIR}/frontend/third_party/*.cpp)


include_directories(${CMAKE_SOURCE_DIR}/frontend/
                    ${CMAKE_SOURCE_DIR}/frontend/utils/
                    ${CMAKE_SOURCE_DIR}/frontend/third_party/)

add_executable(frontend.exe ${SRC_FRONTEND})


#############################################
#            Link our libraries             #
#############################################
#target_link_libraries(frontend.exe libPSI_Tests)
target_link_libraries(frontend.exe -lgmp)
target_link_libraries(frontend.exe libOPRF)
target_link_libraries(frontend.exe libOTe)



