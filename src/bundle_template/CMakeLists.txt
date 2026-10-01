# Rebuild this checker's plugin.so against an installed Clang/LLVM:
#   cmake -S . -B build -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang && cmake --build build
# The result is build/plugin.so; pass it to run_bundle.py with --plugin.
cmake_minimum_required(VERSION 3.13)
project(knighter_checker CXX)

find_package(Clang REQUIRED CONFIG)
message(STATUS "Using Clang ${LLVM_PACKAGE_VERSION} from ${Clang_DIR}")

add_library(checker MODULE checker.cpp utility.cpp)
set_target_properties(checker PROPERTIES PREFIX "" OUTPUT_NAME plugin CXX_STANDARD 17)
target_include_directories(checker PRIVATE include ${CLANG_INCLUDE_DIRS} ${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_definitions(checker PRIVATE ${LLVM_DEFS})
# Export only the two plugin entry points (as LLVM's own plugin build does).
# Without this, statically linked Clang/LLVM symbols in the plugin interpose
# on clang's own copies and the analyzer crashes.
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/plugin.exports"
     "{\n  global:\n    clang_registerCheckers;\n    clang_analyzerAPIVersionString;\n  local: *;\n};\n")
target_link_options(checker PRIVATE
  "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/plugin.exports" -Wl,-z,nodelete -Wl,--gc-sections)
target_compile_options(checker PRIVATE -ffunction-sections -fdata-sections)

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(checker PRIVATE -fno-rtti)
endif()

# Shared libclang-cpp (distribution packages) if it really exists; otherwise the
# static component libraries (a from-source build such as KNighter's own LLVM
# declares the clang-cpp target in its exports without building the file).
set(_shared FALSE)
if(TARGET clang-cpp)
  foreach(_prop IMPORTED_LOCATION_RELEASE IMPORTED_LOCATION_NOCONFIG IMPORTED_LOCATION)
    get_target_property(_loc clang-cpp ${_prop})
    if(_loc AND EXISTS "${_loc}")
      set(_shared TRUE)
    endif()
  endforeach()
endif()
if(_shared)
  message(STATUS "Linking against shared libclang-cpp")
  target_link_libraries(checker PRIVATE clang-cpp LLVM)
else()
  message(STATUS "Linking against static Clang/LLVM component libraries")
  target_link_libraries(checker PRIVATE
    clangStaticAnalyzerFrontend clangStaticAnalyzerCore clangAnalysis clangAST clangBasic LLVMSupport)
endif()
