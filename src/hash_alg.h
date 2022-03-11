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

#ifndef SWINCRYPT_HASH_ALG_H_
#define SWINCRYPT_HASH_ALG_H_

#include <wchar.h>
#include <windows.h>

struct HashAlg {
  ALG_ID hash_alg;
  DWORD provider_type;
};

const struct HashAlg* HashAlg_SearchTable(const wchar_t* alg_name);

int HashAlg_IsSafeForWin9x(ALG_ID hash_alg);

int HashAlg_HashFileData(
    HCRYPTHASH crypt_hash,
    const wchar_t* path,
    const wchar_t* source_file,
    unsigned int line);

#endif /* SWINCRYPT_HASH_ALG_H_ */
