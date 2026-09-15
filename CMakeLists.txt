cmake_minimum_required(VERSION 3.24)
project(rproto
        VERSION 0.1.0
        LANGUAGES C
        DESCRIPTION
        "simple way for get packet from serial port")

file(GLOB RPROTO_SOURCES "*.c")
file(GLOB RPROTO_HEADERS "*.h")
add_library(${PROJECT_NAME} STATIC ${RPROTO_SOURCES} ${RPROTO_HEADERS})

target_include_directories(
        ${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(
        ${PROJECT_NAME} PRIVATE
        rcrc
        rtimeout
        rserial
        rbase64
        rlog
)


#################### FORMAT SECTION #######################

set(FILES_FOR_FORMATTING rproto.c rproto.h rproto_def.h )

if (NOT TARGET rlibhelper)
    include(FetchContent)
    FetchContent_Declare(
            rlibhelper
            GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/rlibhelper.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(rlibhelper)
endif ()

if(EXISTS "${rlibhelper_SOURCE_DIR}/format.cmake")
    include(${rlibhelper_SOURCE_DIR}/format.cmake)
else()
    message(WARNING "format.cmake file not found")
endif()
format_files(${PROJECT_NAME} SOURCES ${FILES_FOR_FORMATTING})


