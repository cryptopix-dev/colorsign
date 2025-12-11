# CMake generated Testfile for 
# Source directory: /Users/siddhuchelluru/Documents/GitHub/ColorSign/macos/sign
# Build directory: /Users/siddhuchelluru/Documents/GitHub/ColorSign/macos/sign/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(BenchmarkTest "/Users/siddhuchelluru/Documents/GitHub/ColorSign/macos/sign/build/benchmark_color_sign_timing")
set_tests_properties(BenchmarkTest PROPERTIES  _BACKTRACE_TRIPLES "/Users/siddhuchelluru/Documents/GitHub/ColorSign/macos/sign/CMakeLists.txt;101;add_test;/Users/siddhuchelluru/Documents/GitHub/ColorSign/macos/sign/CMakeLists.txt;0;")
subdirs("_deps/googletest-build")
subdirs("tests")
