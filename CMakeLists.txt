cmake_minimum_required(VERSION 3.12)

project(hydrogen LANGUAGES C)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

string(TOUPPER "${PROJECT_NAME}" setting_prefix)
function(get_setting setting_name setting_type setting_description)
    string(TOUPPER "${setting_prefix}_${setting_name}" setting_external_name)
    set("${setting_external_name}" "" CACHE "${setting_type}" "${setting_description}")
    set("${setting_name}" "${${setting_external_name}}" PARENT_SCOPE)
endfunction()

# Project files

set(source_files
        "${PROJECT_NAME}.c"
        "impl/common.h"
        "impl/core.h"
        "impl/gimli-core.h"
        "impl/gimli-core/portable.h"
        "impl/gimli-core/sse2.h"
        "impl/hash.h"
        "impl/${PROJECT_NAME}_p.h"
        "impl/kdf.h"
        "impl/kx.h"
        "impl/pwhash.h"
        "impl/random.h"
        "impl/secretbox.h"
        "impl/sign.h"
        "impl/x25519.h")

set(header_files
        "${PROJECT_NAME}.h")

set(test_files
        "tests/tests.c")

# Compile options

get_setting(target_arch STRING "Target system architecture (fed to the compiler's -march=...).")
if(NOT target_arch AND NOT CMAKE_CROSSCOMPILING)
    set(target_arch native)
endif()

set(compile_options
        # GNU, Clang
        $<$<OR:$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:GNU>>:
            # Optimizations
            -Os $<$<BOOL:${target_arch}>:-march=${target_arch}> -fno-exceptions
            # Warnings
            -Wall -Wextra -Wmissing-prototypes -Wdiv-by-zero -Wbad-function-cast -Wcast-align
            -Wcast-qual -Wfloat-equal -Wmissing-declarations -Wnested-externs -Wno-unknown-pragmas
            -Wpointer-arith -Wredundant-decls -Wstrict-prototypes -Wswitch-enum -Wno-type-limits>

        # MSVC
        $<$<C_COMPILER_ID:MSVC>:
            # Optimizations
            /Os /EHsc
            # Warnings
            /WX /W4
            /wd4197 # suppress warning "top-level volatile in cast is ignored"
            /wd4146 # suppress warning "unary minus operator applied to unsigned type, result still unsigned"
            /wd4310 # suppress warning "cast truncates constant value"
        >)

# Prefix project files with the project root

function(prefix_project_paths list_name)
    list(TRANSFORM "${list_name}"
            PREPEND "${PROJECT_SOURCE_DIR}/"
            OUTPUT_VARIABLE prefixed_list)
    set("project_${list_name}" ${prefixed_list} PARENT_SCOPE)
endfunction()

prefix_project_paths(source_files)
prefix_project_paths(header_files)
prefix_project_paths(test_files)

# Main library

add_library("${PROJECT_NAME}")
add_library("${PROJECT_NAME}::${PROJECT_NAME}" ALIAS "${PROJECT_NAME}")

target_sources("${PROJECT_NAME}" PRIVATE ${project_source_files})

target_include_directories("${PROJECT_NAME}" PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_options("${PROJECT_NAME}" PRIVATE ${compile_options})

# Installation

set(targets_export_name "${PROJECT_NAME}-targets")

install(TARGETS "${PROJECT_NAME}"
        EXPORT "${targets_export_name}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(FILES ${project_header_files}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

# CMake find_package() support

set(install_config_dir "${CMAKE_INSTALL_DATADIR}/cmake/${PROJECT_NAME}")

set(targets_export_file_name "${targets_export_name}.cmake")
set(targets_export_file "${PROJECT_BINARY_DIR}/${targets_export_file_name}")

install(EXPORT "${targets_export_name}"
        FILE "${targets_export_file_name}"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "${install_config_dir}")

set(config_file_name "${PROJECT_NAME}-config.cmake")
set(config_template_file "${PROJECT_SOURCE_DIR}/cmake/${config_file_name}.in")
set(config_file "${PROJECT_BINARY_DIR}/${config_file_name}")

CONFIGURE_PACKAGE_CONFIG_FILE("${config_template_file}" "${config_file}"
        INSTALL_DESTINATION "${install_config_dir}")

install(FILES "${config_file}"
        DESTINATION "${install_config_dir}")

export(EXPORT "${targets_export_name}"
        FILE "${targets_export_file}"
        NAMESPACE "${PROJECT_NAME}::")

export(PACKAGE "${PROJECT_NAME}")

# Tests

set(tests_executable "${PROJECT_NAME}-tests")
set(tests_run_target "${PROJECT_NAME}-run-tests")
set(tests_run_file "${PROJECT_BINARY_DIR}/${tests_run_target}.done")

enable_testing()
add_executable("${tests_executable}" ${project_test_files})
target_compile_options("${tests_executable}" PRIVATE ${compile_options})
target_link_libraries("${tests_executable}" "${PROJECT_NAME}")
add_test(NAME "${tests_executable}" COMMAND "${tests_executable}")

if(CMAKE_CROSSCOMPILING)
    # Disable tests executable by default when cross-compiling (as it will fail
    # to build when, e.g., cross-compiling for Arduino/AVR).
    set_target_properties("${tests_executable}"
            PROPERTIES
                EXCLUDE_FROM_ALL 1
                EXCLUDE_FROM_DEFAULT_BUILD 1)
else()
    # Otherwise, auto-run the tests on build.
    add_custom_command(OUTPUT "${tests_run_file}"
            DEPENDS "${tests_executable}"
            COMMAND cmake
                ARGS -E remove "${tests_run_file}"
            COMMAND ctest
                ARGS -C $<CONFIGURATION> --output-on-failure
            COMMAND cmake
                ARGS -E touch "${tests_run_file}"
            WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
    add_custom_target("${tests_run_target}" ALL DEPENDS "${tests_run_file}")
endif()
