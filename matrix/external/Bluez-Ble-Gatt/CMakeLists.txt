# 设置项目名称
project(MyProject)
 
cmake_minimum_required(VERSION 3.10)

# 检查目标平台
if(PLATFORM_X86)
    message("Configuring for x86 platform")
    file(GLOB SOURCE_FILES "src/lib/*.c" "src/src/shared/*.c" "src/adapter/*.c" "src/adapter/ubuntu/*.c")
elseif(PLATFORM_ARM)
    message("Configuring for ARM platform")
    file(GLOB SOURCE_FILES "src/lib/*.c" "src/src/shared/*.c" "src/adapter/*.c" "src/adapter/arm/*.c")

    set(CMAKE_SYSTEM_NAME Linux) # 指定目标系统为Linux
    set(CMAKE_SYSTEM_PROCESSOR arm) # 指定目标处理器为ARM

    # 设置交叉编译工具链的根目录
    set(CMAKE_C_COMPILER arm-openwrt-linux-gcc)
    set(CMAKE_CXX_COMPILER arm-openwrt-linux-g++)
    set(CMAKE_LINKER arm-openwrt-linux-ld)
    set(CMAKE_AR arm-openwrt-linux-ar)

else()
    message(FATAL_ERROR "Platform not specified. Use -DPLATFORM_X86=ON or -DPLATFORM_ARM=ON")
    return()
endif()


add_definitions(-DVERSION="6.56")

# 添加源文件
add_library(libbt-bluez-adapter STATIC ${SOURCE_FILES})
add_library(libbt-bluez-adapter-shared SHARED ${SOURCE_FILES})

target_include_directories(libbt-bluez-adapter PUBLIC src/lib PUBLIC src/)

target_include_directories(libbt-bluez-adapter-shared PUBLIC src/lib PUBLIC src/)

# 添加可执行文件
add_executable(bluez_demo main.c)
add_executable(bluez_demo_shared main.c)

# 链接可执行文件和库
target_link_libraries(bluez_demo libbt-bluez-adapter pthread)
target_link_libraries(bluez_demo_shared libbt-bluez-adapter-shared pthread)

# 输出静态库和动态库到指定目录
set(LIB_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(BIN_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set_target_properties(libbt-bluez-adapter libbt-bluez-adapter-shared bluez_demo bluez_demo_shared PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${LIB_OUTPUT_DIRECTORY}
    LIBRARY_OUTPUT_DIRECTORY ${LIB_OUTPUT_DIRECTORY}
    RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT_DIRECTORY}
    RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT_DIRECTORY}
)

