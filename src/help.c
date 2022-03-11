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

#include "help.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "error.h"
#include "filew.h"
#include "generate.h"
#include "option.h"
#include "win9x.h"

#define LONGEST_OPTION GENERATE_TEXT

enum {
  kTerminalLineCapacity = 72,
  kOptionMaxLength =
      sizeof(LONGEST_OPTION) / sizeof(LONGEST_OPTION[0]) - 1,
  kOptionMaxLineLength = kOptionMaxLength + 1,
  kDescriptionMaxLineLength = kTerminalLineCapacity - kOptionMaxLineLength - 1
};

static void PrintOption(const wchar_t* option, const wchar_t* description) {
  size_t i;
  size_t i_line_start;
  size_t i_line_end;

  size_t description_length;

  wchar_t format_buffer[kDescriptionMaxLineLength];

  /* Generate the appropriate format. */
  description_length = wcslen(description);
  _snwprintf(
      format_buffer,
      kDescriptionMaxLineLength,
      L"%-*s",
      kOptionMaxLineLength,
      option);
  wcscat(format_buffer, L"%-*.*s\n");

  i_line_start = 0;
  i_line_end = 0;

  for (i = 0; description[i] != L'\0'; ++i) {
    if ((i - i_line_start) >= kDescriptionMaxLineLength) {
      wprintf(
          format_buffer,
          kDescriptionMaxLineLength,
          i_line_end - i_line_start,
          &description[i_line_start]);
      if (format_buffer[0] != L' ') {
        _snwprintf(
            format_buffer,
            kDescriptionMaxLineLength,
            L"%*s",
            kOptionMaxLineLength,
            L"");
        wcscat(format_buffer, L"%-*.*s\n");
      }
      i_line_start = i_line_end + 1;
      i = i_line_end;
      continue;
    }

    if (description[i] == L' ') {
      i_line_end = i;
    }
  }

  wprintf(
      format_buffer,
      kDescriptionMaxLineLength,
      kDescriptionMaxLineLength,
      &description[i_line_start]);
}

/**
 * External
 */

void Help_PrintGeneral(void) {
  wprintf(L"Options:\n");
  wprintf(L"=====================================================================\n");
  PrintOption(
      GENERATE_TEXT,
      L"Generate a public/private key pair.");
  PrintOption(
      SIGN_TEXT,
      L"Sign a file using a private key.");
  PrintOption(
      VERIFY_TEXT,
      L"Verify that a digital signature matches with a given file and " \
      L"verification key.");
}

void Help_PrintGenerateOption(void) {
  wprintf(L"%%program%% " GENERATE_TEXT L" [" GENERATE_SIGN_KEY_TYPE_TEXT \
      L"|" GENERATE_ENCDEC_KEY_TYPE_TEXT L"] publickey privatekey\n");
}

void Help_PrintSignOption(void) {
  if (Win9x_IsRunning()) {
    wprintf(L"Windows 95/98/ME only support up to SHA-1.\n");
  }

  wprintf(L"%%program%% " SIGN_TEXT \
      L" [md2|md4|md5|sha-1|sha-256|sha-384|sha-512] " \
      L"privatekey inputfile outputfile\n");
}

void Help_PrintVerifyOption(void) {
  if (Win9x_IsRunning()) {
    wprintf(L"Windows 95/98/ME only support up to SHA-1.\n");
  }

  wprintf(L"%%program%% " VERIFY_TEXT \
      L" [md2|md4|md5|sha-1|sha-256|sha-384|sha-512] " \
      L"publickey inputfile signaturefile\n");
}
