# Cross-compilation file for freestanding WebAssembly.

# To use, pass -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-freestanding-toolchain.cmake on the CMake command line.
# The application has to provide arc4random_buf().

cmake_minimum_required(VERSION 3.12)

set(project_setting_prefix HYDROGEN)
set(setting_prefix "${project_setting_prefix}_WASM32_FREESTANDING")

# Locate toolchain programs

set(program_prefix "${setting_prefix}_PROGRAM")
function(find_in_toolchain program_name)
  string(TOUPPER "${program_prefix}_${program_name}" program_external_name)
  string(REPLACE "_" "-" program_file_name "${program_name}")

  find_program("${program_external_name}" "${program_file_name}")

  if("${${program_external_name}}" STREQUAL "${program_external_name}-NOTFOUND")
    message(FATAL_ERROR "Couldn't find toolchain program ${program_file_name}")
  else()
    set("${program_name}" "${${program_external_name}}" PARENT_SCOPE)
  endif()
endfunction()

find_in_toolchain(clang)
find_in_toolchain(llvm_ranlib)
find_in_toolchain(llvm_ar)
find_in_toolchain(llvm_nm)
find_in_toolchain(llvm_strip)

# Configure CMake toolchain settings

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
set(CMAKE_C_COMPILER "${clang}")
set(CMAKE_ASM_COMPILER "${clang}")
set(CMAKE_RANLIB "${llvm_ranlib}")
set(CMAKE_AR "${llvm_ar}")
set(CMAKE_NM "${llvm_nm}")
set(CMAKE_STRIP "${llvm_strip}")

set(CMAKE_C_OUTPUT_EXTENSION .o)
set(CMAKE_ASM_OUTPUT_EXTENSION .o)

# The compiler check can't link an executable without a libc.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# Set compile flags

set(CMAKE_C_FLAGS_INIT "--target=wasm32-unknown-unknown -ffreestanding")
