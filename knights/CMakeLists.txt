cmake_minimum_required(VERSION 3.20)
project(knights CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

include(FetchContent)

# Dear ImGui
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.92.8
    GIT_SHALLOW TRUE)

# SDL3
set(SDL_SHARED OFF CACHE BOOL "" FORCE)
set(SDL_STATIC ON CACHE BOOL "" FORCE)
set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
set(SDL_TESTS OFF CACHE BOOL "" FORCE)
set(SDL_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SDL_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(SDL3
    GIT_REPOSITORY https://github.com/libsdl-org/SDL.git
    GIT_TAG release-3.4.8
    GIT_SHALLOW TRUE)

FetchContent_MakeAvailable(imgui SDL3)

# Build ImGui (core + SDL3 backend + OpenGL3 backend) as a static lib
add_library(imgui_lib STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl3.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp)
target_include_directories(imgui_lib PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends)
target_link_libraries(imgui_lib PUBLIC SDL3::SDL3-static)

if(EMSCRIPTEN)
    target_compile_definitions(imgui_lib PUBLIC IMGUI_IMPL_OPENGL_ES3)
endif()

add_executable(knights
    src/main.cpp
    src/leaper.cpp
    src/board.cpp
    src/simulation.cpp
    src/renderer.cpp
    src/ui.cpp)

target_link_libraries(knights PRIVATE imgui_lib)

if(EMSCRIPTEN)
    target_link_options(knights PRIVATE
        "SHELL:-sMIN_WEBGL_VERSION=2"
        "SHELL:-sMAX_WEBGL_VERSION=2"
        "SHELL:-sFULL_ES3=1"
        "SHELL:-sALLOW_MEMORY_GROWTH=1"
        "SHELL:-sNO_EXIT_RUNTIME=1"
        "SHELL:-sASSERTIONS=1"
        "SHELL:--shell-file ${CMAKE_SOURCE_DIR}/shell.html")
    set_target_properties(knights PROPERTIES
        OUTPUT_NAME "index"
        SUFFIX ".html"
        LINK_DEPENDS "${CMAKE_SOURCE_DIR}/shell.html")

    # Default install location: <build>/dist. The emcmake toolchain sets
    # CMAKE_INSTALL_PREFIX to the Emscripten sysroot, which is wrong for a
    # web app — override that pathological default but still honor an
    # explicit `--prefix` from the user.
    if(CMAKE_INSTALL_PREFIX MATCHES "[Ss]ysroot")
        set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/dist"
            CACHE PATH "Install destination" FORCE)
    endif()
    install(FILES
        "$<TARGET_FILE_DIR:knights>/index.html"
        "$<TARGET_FILE_DIR:knights>/index.js"
        "$<TARGET_FILE_DIR:knights>/index.wasm"
        DESTINATION ".")
else()
    find_package(OpenGL REQUIRED)
    target_link_libraries(knights PRIVATE OpenGL::GL)
    if(APPLE)
        target_compile_definitions(knights PRIVATE GL_SILENCE_DEPRECATION)
    endif()
    install(TARGETS knights RUNTIME DESTINATION bin)
endif()
