# Simple Windows Cryptography
# Copyright (C) 2022  Mir Drualga
#
# This file is part of Simple Windows Cryptography.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program. If not, see
# <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.11)

# Name of the project, also is the name of the file
project(swincrypt)

# Define requirements for C
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Unicode defintions
add_definitions(-DUNICODE -D_UNICODE)

# Remove MinGW compiled binary "lib" prefix
if (MINGW)
    set(CMAKE_IMPORT_LIBRARY_PREFIX "")
    set(CMAKE_SHARED_LIBRARY_PREFIX "")
    set(CMAKE_STATIC_LIBRARY_PREFIX "")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -municode")
endif (MINGW)

# List all of the source files here
set(RESOURCE_FILES
    "resource/resource.rc"
)

set(SOURCE_FILES
    ${RESOURCE_FILES}

    "src/concat_macro.h"

    "src/error.c"
    "src/error.h"

    "src/file.c"
    "src/file.h"

    "src/filew.h"

    "src/generate.c"
    "src/generate.h"

    "src/hash_alg.c"
    "src/hash_alg.h"

    "src/help.c"
    "src/help.h"

    "src/license.c"
    "src/license.h"

    "src/main.c"

    "src/option.c"
    "src/option.h"

    "src/sign.c"
    "src/sign.h"

    "src/verify.c"
    "src/verify.h"

    "src/win32_crypt.c"
    "src/win32_crypt.h"

    "src/win9x.c"
    "src/win9x.h"
)

# Output DLL
add_executable(${PROJECT_NAME} WIN32 ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} shlwapi)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCE_FILES})
