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

#include "verify.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>

#include "error.h"
#include "file.h"
#include "filew.h"
#include "hash_alg.h"
#include "win32_crypt.h"
#include "win9x.h"

static int ImportKey(
    HCRYPTPROV crypt_provider,
    HCRYPTKEY* crypt_key,
    const wchar_t* path) {
  /* Static avoids stack limits. */
  static unsigned char key_data[FileLimit_kKeySize];

  BOOL is_crypt_import_key_success;

  long file_size;

  file_size = File_GetSize(path, __FILEW__, __LINE__);
  if (file_size > FileLimit_kKeySize) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"Key file size exceeds expected limits.");
    goto bad;
  }

  File_ReadContent(key_data, path, file_size, __FILEW__, __LINE__);

  is_crypt_import_key_success = CryptImportKey(
      crypt_provider,
      key_data,
      file_size,
      0,
      0,
      crypt_key);
  if (!is_crypt_import_key_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptImportKey failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  return 1;

bad:
  return 0;
}

static int VerifySignatureFile(
    HCRYPTHASH crypt_hash,
    HCRYPTKEY crypt_key,
    const wchar_t* signature_path) {
  /* Static avoids stack limits. */
  static unsigned char signature[FileLimit_kSignatureSize];

  BOOL is_crypt_verify_signature_success;

  size_t signature_size;

  signature_size = File_GetSize(signature_path, __FILEW__, __LINE__);
  if (signature_size > FileLimit_kSignatureSize) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"Signature file size exceeds expected limits.");
    goto bad;
  }

  File_ReadContent(
      signature,
      signature_path,
      signature_size,
      __FILEW__,
      __LINE__);

  is_crypt_verify_signature_success = Win32_CryptVerifySignature(
      crypt_hash,
      signature,
      signature_size,
      crypt_key,
      NULL,
      NULL,
      0);
  if (!is_crypt_verify_signature_success) {
    DWORD last_error;

    last_error = GetLastError();
    printf("Signature DOES NOT match with the specified file and key.\n");
    printf("Reason: 0x%X\n", last_error);
  } else {
    printf("Signature matches with the specified file and key.\n");
  }

  return 1;

bad:
  return 0;
}

static int VerifySignature(
    ALG_ID hash_alg,
    DWORD provider_type,
    const wchar_t* key_path,
    const wchar_t* input_path,
    const wchar_t* signature_path) {
  BOOL is_crypt_acquire_context_success;
  int is_import_key_success;
  BOOL is_crypt_create_hash_success;
  int is_hash_file_data_success;
  int is_verified_signature;
  BOOL is_crypt_destroy_hash_success;
  BOOL is_crypt_destroy_key_success;
  BOOL is_crypt_release_context_success;

  HCRYPTPROV crypt_provider;
  HCRYPTKEY crypt_key;
  HCRYPTHASH crypt_hash;

  is_crypt_acquire_context_success = Win32_CryptAcquireContext(
      &crypt_provider,
      NULL,
      NULL,
      NULL,
      NULL,
      provider_type,
      CRYPT_VERIFYCONTEXT);
  if (!is_crypt_acquire_context_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptAcquireContextW failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  is_import_key_success = ImportKey(crypt_provider, &crypt_key, key_path);
  if (!is_import_key_success) {
    Error_ExitWithFormatMessage(__FILEW__, __LINE__, L"ImportKey failed.");
    goto crypt_release_context;
  }

  is_crypt_create_hash_success = CryptCreateHash(
      crypt_provider,
      hash_alg,
      0,
      0,
      &crypt_hash);
  if (!is_crypt_create_hash_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptCreateHash failed with error code 0x%X.",
        GetLastError());
    goto crypt_destroy_key;
  }

  is_hash_file_data_success = HashAlg_HashFileData(
      crypt_hash,
      input_path,
      __FILEW__,
      __LINE__);
  if (!is_hash_file_data_success) {
    Error_ExitWithFormatMessage(__FILEW__, __LINE__, L"HashFileData failed.");
    goto crypt_destroy_hash;
  }

  is_verified_signature = VerifySignatureFile(
      crypt_hash,
      crypt_key,
      signature_path);

  is_crypt_destroy_hash_success = CryptDestroyHash(crypt_hash);
  if (!is_crypt_destroy_hash_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptDestroyHash failed with error code 0x%X.",
        GetLastError());
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
  if (!is_crypt_acquire_context_success) {
    Error_ExitWithFormatMessage(
        __FILEW__,
        __LINE__,
        L"CryptReleaseContext failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  return 1;

crypt_destroy_hash:
  CryptDestroyHash(crypt_hash);

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

int Cryptography_VerifySignature(int argc, wchar_t** argv) {
  const wchar_t* alg_name;
  const wchar_t* key_path;
  const wchar_t* input_path;
  const wchar_t* signature_path;

  const struct HashAlg* hash_alg;

  alg_name = argv[2];
  key_path = argv[3];
  input_path = argv[4];
  signature_path = argv[5];

  hash_alg = HashAlg_SearchTable(alg_name);
  if (hash_alg == NULL) {
    return 0;
  }

  if (Win9x_IsRunning() && !HashAlg_IsSafeForWin9x(hash_alg->hash_alg)) {
    return 0;
  }

  return VerifySignature(
      hash_alg->hash_alg,
      hash_alg->provider_type,
      key_path,
      input_path,
      signature_path);
}
