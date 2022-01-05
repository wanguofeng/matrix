# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite

# Include any dependencies generated for this target.
include CMakeFiles/unqlite.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/unqlite.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/unqlite.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/unqlite.dir/flags.make

CMakeFiles/unqlite.dir/unqlite.c.o: CMakeFiles/unqlite.dir/flags.make
CMakeFiles/unqlite.dir/unqlite.c.o: unqlite.c
CMakeFiles/unqlite.dir/unqlite.c.o: CMakeFiles/unqlite.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/unqlite.dir/unqlite.c.o"
	/home/wanguofeng/Workspace/miio_bt_platform2/miio_bt_builder/toolchains/toolchain-arm-linux-gnueabihf-6.3.1/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/unqlite.dir/unqlite.c.o -MF CMakeFiles/unqlite.dir/unqlite.c.o.d -o CMakeFiles/unqlite.dir/unqlite.c.o -c /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite/unqlite.c

CMakeFiles/unqlite.dir/unqlite.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/unqlite.dir/unqlite.c.i"
	/home/wanguofeng/Workspace/miio_bt_platform2/miio_bt_builder/toolchains/toolchain-arm-linux-gnueabihf-6.3.1/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite/unqlite.c > CMakeFiles/unqlite.dir/unqlite.c.i

CMakeFiles/unqlite.dir/unqlite.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/unqlite.dir/unqlite.c.s"
	/home/wanguofeng/Workspace/miio_bt_platform2/miio_bt_builder/toolchains/toolchain-arm-linux-gnueabihf-6.3.1/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite/unqlite.c -o CMakeFiles/unqlite.dir/unqlite.c.s

# Object files for target unqlite
unqlite_OBJECTS = \
"CMakeFiles/unqlite.dir/unqlite.c.o"

# External object files for target unqlite
unqlite_EXTERNAL_OBJECTS =

libunqlite.a: CMakeFiles/unqlite.dir/unqlite.c.o
libunqlite.a: CMakeFiles/unqlite.dir/build.make
libunqlite.a: CMakeFiles/unqlite.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libunqlite.a"
	$(CMAKE_COMMAND) -P CMakeFiles/unqlite.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/unqlite.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/unqlite.dir/build: libunqlite.a
.PHONY : CMakeFiles/unqlite.dir/build

CMakeFiles/unqlite.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/unqlite.dir/cmake_clean.cmake
.PHONY : CMakeFiles/unqlite.dir/clean

CMakeFiles/unqlite.dir/depend:
	cd /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite /home/wanguofeng/Workspace/myself/matrix/matrix/external/unqlite/CMakeFiles/unqlite.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/unqlite.dir/depend
