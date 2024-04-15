cmake_minimum_required(VERSION 3.29)

project(traceroute)

# Build googletest
add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/googletest"
    "googletest"
)

# Main target
add_executable(
    ${PROJECT_NAME}
    src/exception.h
    src/main.cpp
    src/traceroute.cpp
    src/traceroute.h
)

# Test target
add_executable(
    test_traceroute
    test/test_traceroute.cpp
    src/exception.h
    src/traceroute.cpp
    src/traceroute.h
)

# Add src to the include directories for the target
target_include_directories(
    test_traceroute PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

# Link test target against gtest libraries
target_link_libraries(
    test_traceroute PRIVATE
    gtest gtest_main
)

if (MSVC)
    # to build gtest on windows
    # gtest - static runtime
    # all other world - dynamic runtime
    # https://github.com/google/googletest/blob/master/googletest/README.md
    # Visual Studio Dynamic vs Static Runtimes
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    target_compile_options(
        # flags for additional logging
        ${PROJECT_NAME} PRIVATE
        /W4
    )
    target_compile_options(
        # flags for additional logging
        test_traceroute PRIVATE
        /W4
    )
else()
    target_compile_options(
        # flags for additional logging
        ${PROJECT_NAME} PRIVATE
        -Wall -Wextra -pedantic -Werror
    )
    target_compile_options(
        # flags for additional logging
        test_traceroute PRIVATE
        -Wall -Wextra -pedantic -Werror
    )
endif()
