cmake_minimum_required(VERSION 3.24)
project(rproto
        VERSION 0.1.0
        LANGUAGES C
        DESCRIPTION
        "simple way for get packet from serial port")

file(GLOB RPROTO_SOURCES "*.c")
file(GLOB RPROTO_HEADERS "*.h")
add_library(${PROJECT_NAME} STATIC ${RPROTO_SOURCES} ${RPROTO_HEADERS})

# Performance test sources (part of rproto_test)
file(GLOB RPROTO_PERF_SOURCES test/perf_test.c test/perf_emu.c test/perf_emu_ipc.c)
file(GLOB RPROTO_PERF_HEADERS test/perf_test.h test/perf_emu.h test/perf_emu_ipc.h)

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

if (NOT TARGET rlog)
    include(FetchContent)
    FetchContent_Declare(
            rlog
            GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/rlog.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(rlog)
endif ()

if (NOT TARGET rtimeout)
    include(FetchContent)
    FetchContent_Declare(
            rtimeout
            GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/rtimeout.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(rtimeout)
endif ()

if (NOT TARGET rcrc)
    include(FetchContent)
    FetchContent_Declare(
            rcrc
            GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/rcrc.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(rcrc)
endif ()

if (NOT TARGET rserial)
    include(FetchContent)
    FetchContent_Declare(
            rserial
            GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/rserial.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(rserial)
endif ()

if (NOT TARGET rbase64)
    include(FetchContent)
    FetchContent_Declare(
            rbase64
            GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/rbase64.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(rbase64)
endif ()

if (NOT TARGET runit)
    include(FetchContent)
    FetchContent_Declare(
            runit
            GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/runit.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(runit)
endif ()

#################### TEST SECTION #######################
add_executable(${PROJECT_NAME}_test test/test.c ${RPROTO_PERF_SOURCES})
target_include_directories(${PROJECT_NAME}_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/test
)
target_link_libraries(${PROJECT_NAME}_test rproto runit rcrc rbase64 rserial rlog pthread)

enable_testing()


add_test(NAME socat_start COMMAND ${CMAKE_CURRENT_LIST_DIR}/test/socat_start.sh start)
add_test(NAME socat_stop COMMAND ${CMAKE_CURRENT_LIST_DIR}/test/socat_start.sh stop)
add_test(NAME ${PROJECT_NAME}_test COMMAND ${PROJECT_NAME}_test)

set_tests_properties(socat_start PROPERTIES FIXTURES_SETUP socat)
set_tests_properties(socat_stop PROPERTIES FIXTURES_CLEANUP socat)
set_tests_properties(${PROJECT_NAME}_test PROPERTIES FIXTURES_REQUIRED "socat")


#################### FORMAT SECTION #######################

set(FILES_FOR_FORMATTING
        ${RPROTO_SOURCES}
        ${RPROTO_HEADERS}
        ${RPROTO_PERF_SOURCES}
        ${RPROTO_PERF_HEADERS}
        test/test.c
)

if (NOT TARGET rlibhelper)
    include(FetchContent)
    FetchContent_Declare(
            rlibhelper
            GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/rlibhelper.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(rlibhelper)
endif ()

if (EXISTS "${rlibhelper_SOURCE_DIR}/format.cmake")
    include(${rlibhelper_SOURCE_DIR}/format.cmake)
else ()
    message(WARNING "format.cmake file not found")
endif ()
format_files(${PROJECT_NAME} SOURCES ${FILES_FOR_FORMATTING})


