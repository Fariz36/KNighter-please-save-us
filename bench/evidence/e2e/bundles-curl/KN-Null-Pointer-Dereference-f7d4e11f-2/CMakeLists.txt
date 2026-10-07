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
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(checker PRIVATE -fno-rtti)
endif()

# Shared libclang-cpp (distribution packages) or the static component libraries
# (a from-source build such as KNighter's own LLVM).
if(TARGET clang-cpp)
  target_link_libraries(checker PRIVATE clang-cpp LLVM)
else()
  target_link_libraries(checker PRIVATE
    clangStaticAnalyzerFrontend clangStaticAnalyzerCore clangAnalysis clangAST clangBasic LLVMSupport)
endif()
