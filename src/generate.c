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

#include "generate.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "concat_macro.h"
#include "error.h"
#include "file.h"
#include "filew.h"
#include "win32_crypt.h"

#define KEY_CONTAINER_NAME_ANSI \
    "SimpleWindowsCryptography_KeyContainer_Generate"
#define KEY_CONTAINER_NAME_WIDE CONCAT_MACROS(L, KEY_CONTAINER_NAME_ANSI)

struct KeyPairTypeTableEntry {
  const wchar_t* key;
  ALG_ID value;
};

static int KeyPairTypeTableEntry_CompareKey(
    const struct KeyPairTypeTableEntry* entry1,
    const struct KeyPairTypeTableEntry* entry2) {
  return wcscmp(entry1->key, entry2->key);
}

static int KeyPairTypeTableEntry_CompareKeyAsVoid(
    const void* entry1,
    const void* entry2) {
  return KeyPairTypeTableEntry_CompareKey(entry1, entry2);
}

const struct KeyPairTypeTableEntry kSortedKeyPairTypeTable[] = {
  { GENERATE_ENCDEC_KEY_TYPE_TEXT, AT_KEYEXCHANGE },
  { GENERATE_SIGN_KEY_TYPE_TEXT, AT_SIGNATURE },
};

enum {
  kSortedKeyPairTypeTableCount = sizeof(kSortedKeyPairTypeTable)
      / sizeof(kSortedKeyPairTypeTable[0]),
};

static int ExportKeyToFile(
    HCRYPTKEY crypt_key,
    const wchar_t* key_path,
    DWORD key_type) {
  /* Static avoids stack limits. */
  static unsigned char key_data[FileLimit_kKeySize];

  BOOL is_crypt_export_key_success;

  DWORD key_size;

  is_crypt_export_key_success = CryptExportKey(
      crypt_key,
      0,
      key_type,
      0,
      NULL,
      &key_size);
  if (!is_crypt_export_key_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptExportKey failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  if (key_size > FileLimit_kKeySize) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"Key size exceeds expected limits.");
    goto bad;
  }

  is_crypt_export_key_success = CryptExportKey(
      crypt_key,
      0,
      key_type,
      0,
      key_data,
      &key_size);
  if (!is_crypt_export_key_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptExportKey failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  File_WriteContentToFile(key_path, key_data, key_size, __FILEW__, __LINE__);
  return 1;

bad:
  return 0;
}

static int GeneratePubPrivKey(
    ALG_ID key_pair_type,
    const wchar_t* public_key_path,
    const wchar_t* private_key_path) {
  BOOL is_crypt_acquire_context_success;
  BOOL is_crypt_gen_key_success;
  BOOL is_export_key_success;
  BOOL is_crypt_destroy_key_success;
  BOOL is_crypt_release_context_success;

  HCRYPTPROV crypt_provider;
  HCRYPTKEY crypt_key;

  Win32_CryptAcquireContext(
      &crypt_provider,
      KEY_CONTAINER_NAME_ANSI,
      KEY_CONTAINER_NAME_WIDE,
      NULL,
      NULL,
      PROV_RSA_FULL,
      CRYPT_DELETEKEYSET);

  is_crypt_acquire_context_success = Win32_CryptAcquireContext(
      &crypt_provider,
      KEY_CONTAINER_NAME_ANSI,
      KEY_CONTAINER_NAME_WIDE,
      NULL,
      NULL,
      PROV_RSA_FULL,
      CRYPT_NEWKEYSET);
  if (!is_crypt_acquire_context_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptAcquireContextW failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  is_crypt_gen_key_success = CryptGenKey(
      crypt_provider,
      key_pair_type,
      CRYPT_EXPORTABLE,
      &crypt_key);
  if (!is_crypt_gen_key_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptGenKey failed with error code 0x%X.",
        GetLastError());
    goto crypt_release_context;
  }

  is_export_key_success = ExportKeyToFile(crypt_key, public_key_path, PUBLICKEYBLOB);
  if (!is_export_key_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"ExportKeyToFile failed.");
    goto crypt_destroy_key;
  }

  is_export_key_success = ExportKeyToFile(
      crypt_key,
      private_key_path,
      PRIVATEKEYBLOB);
  if (!is_export_key_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"ExportKeyToFile failed.");
    goto crypt_destroy_key;
  }

  is_crypt_destroy_key_success = CryptDestroyKey(crypt_key);
  if (!is_crypt_destroy_key_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptDestroyKey failed with error code 0x%X.",
        GetLastError());
    goto crypt_release_context;
  }

  is_crypt_release_context_success = CryptReleaseContext(crypt_provider, 0);
  if (!is_crypt_release_context_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptReleaseContext failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  is_crypt_acquire_context_success = Win32_CryptAcquireContext(
      &crypt_provider,
      KEY_CONTAINER_NAME_ANSI,
      KEY_CONTAINER_NAME_WIDE,
      NULL,
      NULL,
      PROV_RSA_FULL,
      CRYPT_DELETEKEYSET);
  if (!is_crypt_acquire_context_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptAcquireContextW failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  return 1;

crypt_destroy_key:
  CryptDestroyKey(crypt_key);

crypt_release_context:
  CryptReleaseContext(crypt_provider, 0);

bad:
  return 0;
}

/**
 * External
 */

int Cryptography_GeneratePubPrivKey(int argc, wchar_t** argv) {
  const wchar_t* key_pair_type;
  const wchar_t* public_key_path;
  const wchar_t* private_key_path;

  const struct KeyPairTypeTableEntry* search_result;

  key_pair_type = argv[2];
  public_key_path = argv[3];
  private_key_path = argv[4];

  search_result = bsearch(
      &key_pair_type,
      kSortedKeyPairTypeTable,
      kSortedKeyPairTypeTableCount,
      sizeof(kSortedKeyPairTypeTable[0]),
      &KeyPairTypeTableEntry_CompareKeyAsVoid);

  if (search_result == NULL) {
    return 0;
  }

  return GeneratePubPrivKey(
      search_result->value,
      public_key_path,
      private_key_path);
}
