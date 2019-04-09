cmake_minimum_required(VERSION 3.10)

project(hydrogen
        LANGUAGES C)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(compile_options
        $<$<OR:$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:GNU>>:
            # Optimizations
            -Os -march=native -fno-exceptions
            # Warnings
            -Wall -Wextra -Wmissing-prototypes -Wdiv-by-zero -Wbad-function-cast -Wcast-align
            -Wcast-qual -Wfloat-equal -Wmissing-declarations -Wnested-externs -Wno-unknown-pragmas
            -Wpointer-arith -Wredundant-decls -Wstrict-prototypes -Wswitch-enum -Wno-type-limits>
        $<$<C_COMPILER_ID:MSVC>:
            # Optimizations
            /Os /EHsc
            # Warnings
            /WX /W4
            /wd4197 # suppress warning "top-level volatile in cast is ignored"
            /wd4146 # suppress warning "unary minus operator applied to unsigned type, result still unsigned"
            /wd4310 # suppress warning "cast truncates constant value"
        >)

set(source_files
        "${PROJECT_SOURCE_DIR}/${PROJECT_NAME}.c"
        "${PROJECT_SOURCE_DIR}/impl/common.h"
        "${PROJECT_SOURCE_DIR}/impl/core.h"
        "${PROJECT_SOURCE_DIR}/impl/gimli-core.h"
        "${PROJECT_SOURCE_DIR}/impl/gimli-core/portable.h"
        "${PROJECT_SOURCE_DIR}/impl/gimli-core/sse2.h"
        "${PROJECT_SOURCE_DIR}/impl/hash.h"
        "${PROJECT_SOURCE_DIR}/impl/${PROJECT_NAME}_p.h"
        "${PROJECT_SOURCE_DIR}/impl/kdf.h"
        "${PROJECT_SOURCE_DIR}/impl/kx.h"
        "${PROJECT_SOURCE_DIR}/impl/pwhash.h"
        "${PROJECT_SOURCE_DIR}/impl/random.h"
        "${PROJECT_SOURCE_DIR}/impl/secretbox.h"
        "${PROJECT_SOURCE_DIR}/impl/sign.h"
        "${PROJECT_SOURCE_DIR}/impl/x25519.h")
set(header_files
        "${PROJECT_SOURCE_DIR}/${PROJECT_NAME}.h")
set(test_files
        "${PROJECT_SOURCE_DIR}/tests/tests.c")

set(config_file_name "${PROJECT_NAME}-config.cmake")
set(config_template_file "${PROJECT_SOURCE_DIR}/${config_file_name}.in")
set(config_file "${PROJECT_BINARY_DIR}/${config_file_name}")

set(targets_export_name "${PROJECT_NAME}-targets")
set(targets_export_file_name "${targets_export_name}.cmake")
set(targets_export_file "${PROJECT_BINARY_DIR}/${targets_export_file_name}")

set(install_config_dir "${CMAKE_INSTALL_DATADIR}/cmake/${PROJECT_NAME}")

set(tests_executable "${PROJECT_NAME}-tests")
set(tests_done_target "${tests_executable}-done")
set(tests_done_file "${PROJECT_BINARY_DIR}/${tests_executable}.done")

# Main library

add_library("${PROJECT_NAME}")
add_library("${PROJECT_NAME}::${PROJECT_NAME}" ALIAS "${PROJECT_NAME}")

target_sources("${PROJECT_NAME}" PRIVATE ${source_files})

target_include_directories("${PROJECT_NAME}" PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_options(${PROJECT_NAME} PRIVATE ${compile_options})

# Installation

install(TARGETS "${PROJECT_NAME}"
        EXPORT "${targets_export_name}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(FILES ${header_files}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

# CMake find_package() support

install(EXPORT "${targets_export_name}"
        FILE "${targets_export_file_name}"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "${install_config_dir}")

CONFIGURE_PACKAGE_CONFIG_FILE("${config_template_file}" "${config_file}"
        INSTALL_DESTINATION "${install_config_dir}")

install(FILES ${config_file}
        DESTINATION ${install_config_dir})

export(EXPORT "${targets_export_name}"
        FILE "${targets_export_file}"
        NAMESPACE "${PROJECT_NAME}::")

export(PACKAGE "${PROJECT_NAME}")

# Tests

enable_testing()
add_executable("${tests_executable}" ${test_files})
target_compile_options("${tests_executable}" PRIVATE ${compile_options})
target_link_libraries("${tests_executable}" "${PROJECT_NAME}")
add_test(NAME "${tests_executable}" COMMAND "${tests_executable}")

# Auto-run tests on build (unless cross-compiling)

if(NOT CMAKE_CROSSCOMPILING)
    add_custom_command(OUTPUT "${tests_done_file}"
            DEPENDS "${tests_executable}"
            COMMAND cmake
                ARGS -E remove "${tests_done_file}"
            COMMAND ctest
                ARGS -C $<CONFIGURATION> --output-on-failure
            COMMAND cmake
                ARGS -E touch "${tests_done_file}"
            WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
    add_custom_target("${tests_done_target}" ALL DEPENDS "${tests_done_file}")
endif()
