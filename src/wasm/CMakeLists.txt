# * ******************************************************************************************************* *
# *
# * Copyright 2024 NXP
# * Copyright 2025 Oidis
# *
# * SPDX-License-Identifier: BSD-3-Clause
# * The BSD-3-Clause license for this file can be found in the LICENSE.txt file included with this distribution
# * or at https://spdx.org/licenses/BSD-3-Clause.html#licenseText
# *
# * ******************************************************************************************************* *

cmake_minimum_required(VERSION 3.16)
project(webix-dapper-wasm)

set(CMAKE_CXX_STANDARD 17)

file(GLOB SRC_FILES src/*.cpp)

set(SOURCE_FILES_MAIN ${SRC_FILES})

include_directories(src)

add_executable(${PROJECT_NAME} ${SOURCE_FILES_MAIN})

set(WASM_TARGETS "${WASM_TARGETS};${PROJECT_NAME}" PARENT_SCOPE)

if (NATIVE_BUILD OR NOT (EMSCRIPTEN))
    add_definitions(-DNATIVE_BUILD)

    set(WASM_COMMON)

    set(WASM_MAIN
            ${WASM_COMMON}
    )
else ()
    set(WASM_COMMON
            "SHELL:-s LLD_REPORT_UNDEFINED"
            "SHELL:-s ALLOW_MEMORY_GROWTH=1"
            "SHELL:-s ASSERTIONS=1"
            "SHELL:-s ASYNCIFY=1"
            "SHELL:-s DISABLE_EXCEPTION_CATCHING=0"
            "SHELL:-s USE_ES6_IMPORT_META=1"
    )

    set(WASM_MAIN
            ${WASM_COMMON}
            "SHELL:-s EXPORT_ES6=1"
            "SHELL:-s MODULARIZE=1"
            "SHELL:-s EXPORT_NAME=dapper"
    )

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --bind")

    if ($ENV{DEBUG})
        # TODO(mkelnar) debug mode causing app inconsistency and its not working but dwarf symbols can be
        #  consumed by browser debuger. Validate this deeply when it will be needed, but it is useless for now.
        message(WARNING "Building with debug symbols. Do not use this build type for production.")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -O1 -g")
    else ()
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -O3")
    endif ()
endif ()

target_compile_options(${PROJECT_NAME} PRIVATE ${WASM_MAIN})
target_link_options(${PROJECT_NAME} PRIVATE ${WASM_MAIN})
