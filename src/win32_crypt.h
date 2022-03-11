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

#ifndef SWINCRYPT_WIN9X_CRYPT_H_
#define SWINCRYPT_WIN9X_CRYPT_H_

#include <windows.h>

BOOL Win32_CryptAcquireContext(
    HCRYPTPROV* crypt_provider,
    LPCSTR container_ansi,
    LPCWSTR container_wide,
    LPCSTR provider_ansi,
    LPCWSTR provider_wide,
    DWORD provider_type,
    DWORD flags);

BOOL Win32_CryptSignHash(
    HCRYPTHASH crypt_hash,
    DWORD key_spec,
    LPCSTR description_ansi,
    LPCWSTR description_wide,
    DWORD flags,
    BYTE* signature,
    DWORD* signature_length);

BOOL Win32_CryptVerifySignature(
    HCRYPTHASH crypt_hash,
    BYTE* signature,
    DWORD signature_length,
    HCRYPTKEY public_key,
    LPCSTR description_ansi,
    LPCWSTR description_wide,
    DWORD dwFlags);

#endif /* SWINCRYPT_WIN9X_CRYPT_H_ */
