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


#################### TEST SECTION #######################
if (NOT ${CMAKE_SYSTEM_NAME} MATCHES Generic)
    add_executable(${PROJECT_NAME}_test test/test.c)
    if (NOT TARGET runit)
        include(FetchContent)
        FetchContent_Declare(
                runit
                GIT_REPOSITORY https://github.com/RoboticsHardwareSolutions/runit.git
                GIT_TAG main
        )
        FetchContent_MakeAvailable(runit)
    endif ()
    target_link_libraries(${PROJECT_NAME}_test rproto runit rcrc rbase64 rserial)
    enable_testing()

    add_test(NAME socatStart COMMAND ${CMAKE_CURRENT_LIST_DIR}/test/socatfortests.sh start)
    add_test(NAME socatStop COMMAND ${CMAKE_CURRENT_LIST_DIR}/test/socatfortests.sh stop)
    add_test(NAME ${PROJECT_NAME}_test COMMAND ${PROJECT_NAME}_test)

    set_tests_properties(socatStart PROPERTIES FIXTURES_SETUP socat)
    set_tests_properties(socatStop PROPERTIES FIXTURES_CLEANUP socat)
    set_tests_properties(${PROJECT_NAME}_test PROPERTIES FIXTURES_REQUIRED "socat")
endif ()

#################### FORMAT SECTION #######################

set(FILES_FOR_FORMATTING
        rproto.c
        rproto.h
        rproto_def.h
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


