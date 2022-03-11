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

#include "win9x.h"

#include <windows.h>

#include "error.h"
#include "filew.h"

static OSVERSIONINFOW global_os_info_version;

static void InitGlobalOsInfoVersion(void) {
  static int is_init = 0;

  BOOL is_get_version_success;

  if (is_init) {
    return;
  }

  global_os_info_version.dwOSVersionInfoSize = sizeof(global_os_info_version);
  is_get_version_success = GetVersionExW(&global_os_info_version);
  if (!is_get_version_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"GetVersionExW failed with error code 0x%X",
        GetLastError());
    goto bad;
  }

  is_init = 1;
  return;

bad:
  return;
}

/**
 * External
 */

int Win9x_IsRunning(void) {
  InitGlobalOsInfoVersion();

  return global_os_info_version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS;
}
