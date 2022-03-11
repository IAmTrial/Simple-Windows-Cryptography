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

#include "hash_alg.h"

#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>

#include "error.h"

/*
 * Code that normally would work, but Windows 9X has a broken _wfopen
 * implementation.
 */
#if 0

int HashAlg_HashFileData(
    HCRYPTHASH crypt_hash,
    const wchar_t* path,
    const wchar_t* source_file,
    unsigned int line) {
  enum {
    kBufferCapacity = 256,
  };

  FILE* file;
  unsigned char buffer[kBufferCapacity];

  file = _wfopen(path, L"rb");
  if (file == NULL) {
    Error_ExitWithFormatMessage(__FILEW__, __LINE__, L"fopen failed.");
    goto bad;
  }

  while (!feof(file)) {
    BOOL is_crypt_hash_data_success;

    size_t bytes_read_count;

    bytes_read_count = fread(buffer, 1, kBufferCapacity, file);
    is_crypt_hash_data_success = CryptHashData(
        crypt_hash,
        buffer,
        bytes_read_count,
        0);
    if (!is_crypt_hash_data_success) {
      Error_ExitWithFormatMessage(
          __FILEW__,
          __LINE__,
          L"CryptHashData failed with error code 0x%X.",
          GetLastError());
      goto fclose_file;
    }
  }

  fclose(file);

  return 1;

fclose_file:
  fclose(file);

bad:
  return 0;
}

#endif


/* Forward compatibility defines for Visual C++ 6.0. */
#if defined(_MSC_VER) && _MSC_VER < 1600

#define ALG_CLASS_HASH (4 << 13)

#define CALG_SHA_256 (ALG_CLASS_HASH | 12)
#define CALG_SHA_384 (ALG_CLASS_HASH | 13)
#define CALG_SHA_512 (ALG_CLASS_HASH | 14)

#define PROV_RSA_AES 24

#endif /* defined(_MSC_VER) && _MSC_VER < 1600 */

struct HashAlgTableEntry {
  const wchar_t* key;
  struct HashAlg value;
};
static int HashAlgTableEntry_CompareKey(
    const struct HashAlgTableEntry* entry1,
    const struct HashAlgTableEntry* entry2) {
  return wcscmp(entry1->key, entry2->key);
}

static int HashAlgTableEntry_CompareKeyAsVoid(
    const void* entry1,
    const void* entry2) {
  return HashAlgTableEntry_CompareKey(entry1, entry2);
}

static const struct HashAlgTableEntry kSortedHashAlgTable[] = {
  { L"md2", { CALG_MD2, PROV_RSA_FULL } },
  { L"md4", { CALG_MD4, PROV_RSA_FULL } },
  { L"md5", { CALG_MD5, PROV_RSA_FULL } },
  { L"sha-1", { CALG_SHA1, PROV_RSA_FULL } },
  { L"sha-256", { CALG_SHA_256, PROV_RSA_AES } },
  { L"sha-384", { CALG_SHA_384, PROV_RSA_AES } },
  { L"sha-512", { CALG_SHA_512, PROV_RSA_AES } },
};

enum {
  kSortedHashAlgTableCount = sizeof(kSortedHashAlgTable)
      / sizeof(kSortedHashAlgTable[0]),
};

static const ALG_ID kSortedSafeForWin9xSet[] = {
  CALG_MD2,
  CALG_MD4,
  CALG_MD5,
  CALG_SHA1,
};

enum {
  kSortedSafeForWin9xSetCount = sizeof(kSortedSafeForWin9xSet)
      / sizeof(kSortedSafeForWin9xSet[0]),
};

static int CompareAlgId(const ALG_ID* hash_alg1, const ALG_ID* hash_alg2) {
  return *hash_alg1 < *hash_alg2;
}

static int CompareAlgIdAsVoid(const void* hash_alg1, const void* hash_alg2) {
  return CompareAlgId(hash_alg1, hash_alg2);
}

/**
 * External
 */

const struct HashAlg* HashAlg_SearchTable(const wchar_t* alg_name) {
  const struct HashAlgTableEntry* search_result; 

  search_result = bsearch(
      &alg_name,
      kSortedHashAlgTable,
      kSortedHashAlgTableCount,
      sizeof(kSortedHashAlgTable[0]),
      &HashAlgTableEntry_CompareKeyAsVoid);

  if (search_result == NULL) {
    return NULL;
  }

  return &search_result->value;
}

int HashAlg_IsSafeForWin9x(ALG_ID hash_alg) {
  const ALG_ID* search_result;

  search_result = bsearch(
      &hash_alg,
      kSortedSafeForWin9xSet,
      kSortedSafeForWin9xSetCount,
      sizeof(kSortedSafeForWin9xSet[0]),
      &CompareAlgIdAsVoid);

  return search_result != NULL;
}

int HashAlg_HashFileData(
    HCRYPTHASH crypt_hash,
    const wchar_t* path,
    const wchar_t* source_file,
    unsigned int line) {
  enum {
    kBufferCapacity = 256,
  };

  BOOL is_read_file_success;

  HANDLE* file;
  DWORD bytes_read_count;
  unsigned char buffer[kBufferCapacity];

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
        source_file,
        line,
        L"CreateFileW failed with error code 0x%X.",
        GetLastError());
    goto bad;
  }

  do {
    BOOL is_crypt_hash_data_success;

    is_read_file_success = ReadFile(
        file,
        buffer,
        kBufferCapacity,
        &bytes_read_count,
        NULL);
    if (!is_read_file_success) {
      Error_ExitWithFormatMessage(
          source_file,
          line,
          L"ReadFile failed with error code 0x%X.",
          GetLastError());
      goto close_file;
    }

    is_crypt_hash_data_success = CryptHashData(
        crypt_hash,
        buffer,
        bytes_read_count,
        0);
    if (!is_crypt_hash_data_success) {
      Error_ExitWithFormatMessage(
          source_file,
          line,
          L"CryptHashData failed with error code 0x%X.",
          GetLastError());
      goto close_file;
    }
  } while (bytes_read_count > 0);

  CloseHandle(file);
  return 1;

close_file:
  CloseHandle(file);

bad:
  return 0;
}
