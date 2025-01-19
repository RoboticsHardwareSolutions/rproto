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



