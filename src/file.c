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

#include "file.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "error.h"
#include "filew.h"

/*
 * Code that normally would work, but Windows 9X has a broken _wfopen
 * implementation.
 */
#if 0

static size_t GetSize(
    FILE* file,
    const wchar_t* source_file,
    unsigned int line) {
  int fseek_result;

  long file_size;

  fseek_result = fseek(file, 0, SEEK_END);
  if (fseek_result != 0) {
    Error_ExitWithFormatMessage(source_file, line, L"fseek failed.");
    goto bad;
  }

  file_size = ftell(file);
  if (file_size == -1L) {
    Error_ExitWithFormatMessage(source_file, line, L"ftell failed.");
    goto bad;
  }

  return (size_t)file_size;

bad:
  return 0;
}

size_t File_GetSize(
    const wchar_t* path,
    const wchar_t* source_file,
    unsigned int line) {
  size_t file_size;

  FILE* file;

  file = _wfopen(path, L"rb");
  if (file == NULL) {
    Error_ExitWithFormatMessage(source_file, line, L"fopen failed.");
    goto bad;
  }

  file_size = GetSize(file, source_file, line);
  fclose(file);

  return file_size;

bad:
  return 0;
}

void File_ReadContent(
    unsigned char* content,
    const wchar_t* path,
    size_t file_size,
    const wchar_t* source_file,
    unsigned int line) {
  FILE* file;

  file = _wfopen(path, L"rb");
  if (file == NULL) {
    Error_ExitWithFormatMessage(source_file, line, L"fopen failed.");
    goto bad;
  }

  fread(content, 1, file_size, file);
  fclose(file);
  return;

bad:
  return;
}

void File_WriteContentToFile_standard(
    const wchar_t* path,
    const void* bytes,
    size_t bytes_size,
    const wchar_t* source_file,
    unsigned int line) {
  FILE* file;

  file = _wfopen(path, L"wb");
  wprintf(L"%ls: %p\n", path, file);
  if (file == NULL) {
    wprintf(L"0x%X\n", errno);
    _wperror(L"_wfopen failed");
    Error_ExitWithFormatMessage(
        source_file,
        line,
        L"_wfopen failed.");
    goto bad;
  }

  fwrite(bytes, 1, bytes_size, file);
  fclose(file);
  return;

bad:
  return;
}

#endif

/**
 * External
 */

size_t File_GetSize(
    const wchar_t* path,
    const wchar_t* source_file,
    unsigned int line) {
  HANDLE file;
  size_t file_size;

  file = CreateFileW(
      path,
      0,
      0,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  if (file == NULL) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CreateFileW failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  file_size = GetFileSize(file, NULL);
  if (file_size == 0xFFFFFFFF) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"GetFileSize failed with error code 0x%X.",
        GetLastError());
    goto close_file;
  }

  CloseHandle(file);
  return file_size;

close_file:
  CloseHandle(file);

bad:
  return 0;
}

void File_ReadContent(
    unsigned char* content,
    const wchar_t* path,
    size_t file_size,
    const wchar_t* source_file,
    unsigned int line) {
  BOOL is_read_file_success;

  HANDLE file;
  DWORD bytes_read_count;

  file = CreateFileW(
      path,
      GENERIC_READ,
      0,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  if (file == NULL) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CreateFileW failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  is_read_file_success = ReadFile(
      file,
      content,
      file_size,
      &bytes_read_count,
      NULL);
  if (!is_read_file_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"ReadFile failed with error code 0x%X.",
        GetLastError());
    goto close_file;
  }

  CloseHandle(file);
  return;

close_file:
  CloseHandle(file);

bad:
  return;
}

void File_WriteContentToFile(
    const wchar_t* path,
    const void* bytes,
    size_t bytes_size,
    const wchar_t* source_file,
    unsigned int line) {
  BOOL is_write_file_success;

  HANDLE file;
  DWORD bytes_written_count;

  file = CreateFileW(
      path,
      GENERIC_WRITE,
      0,
      NULL,
      CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
  if (file == NULL) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CreateFileW failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  is_write_file_success = WriteFile(
      file,
      bytes,
      bytes_size,
      &bytes_written_count,
      NULL);
  if (!is_write_file_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"WriteFile failed with error code 0x%X.",
        GetLastError());
    goto close_file;
  }

  CloseHandle(file);
  return;

close_file:
  CloseHandle(file);

bad:
  return;
}
