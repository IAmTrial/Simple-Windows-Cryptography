/**
 * Simple Windows Cryptography
 * Copyright (C) 2022  Mir Drualga
 *
 * This file is part of Simple Windows Cryptography.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#ifndef SWINCRYPT_FILE_H_
#define SWINCRYPT_FILE_H_

#include <stddef.h>
#include <wchar.h>

enum {
  /* 1MB limit for file size. */
  FileLimit_kKeySize = 1000000,
  FileLimit_kSignatureSize = 1000000,
};

size_t File_GetSize(
    const wchar_t* path,
    const wchar_t* source_file,
    unsigned int line);

void File_ReadContent(
    unsigned char* content,
    const wchar_t* path,
    size_t file_size,
    const wchar_t* source_file,
    unsigned int line);

void File_WriteContentToFile(
    const wchar_t* path,
    const void* bytes,
    size_t bytes_size,
    const wchar_t* source_file,
    unsigned int line);

#endif /* SWINCRYPT_FILE_H_ */
