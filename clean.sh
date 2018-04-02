#!/bin/sh

# clean cmake files
find . -name "CMakeCache.txt" | xargs rm -rf
find . -name "cmake_install.cmake" | xargs rm -rf
find . -name "Makefile" | xargs rm -rf
find . -name "CMakeFiles" | xargs rm -rf

# clean eclipse project files
find . -name ".cproject" | xargs rm -rf
find . -name ".project" | xargs rm -rf

# clean executable file
find . -name "fake_bitfiend" | xargs rm -rf
