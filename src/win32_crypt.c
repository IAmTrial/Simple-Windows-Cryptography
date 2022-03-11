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

#include "win32_crypt.h"

#include <windows.h>

#include "win9x.h"

BOOL Win32_CryptAcquireContext(
    HCRYPTPROV* crypt_provider,
    LPCSTR container_ansi,
    LPCWSTR container_wide,
    LPCSTR provider_ansi,
    LPCWSTR provider_wide,
    DWORD provider_type,
    DWORD flags) {
  if (Win9x_IsRunning()) {
    return CryptAcquireContextA(
        crypt_provider,
        container_ansi,
        provider_ansi,
        provider_type,
        flags);
  } else {
    return CryptAcquireContextW(
        crypt_provider,
        container_wide,
        provider_wide,
        provider_type,
        flags);
  }
}

BOOL Win32_CryptSignHash(
    HCRYPTHASH crypt_hash,
    DWORD key_spec,
    LPCSTR description_ansi,
    LPCWSTR description_wide,
    DWORD flags,
    BYTE* signature,
    DWORD* signature_length) {
  if (Win9x_IsRunning()) {
    return CryptSignHashA(
        crypt_hash,
        key_spec,
        description_ansi,
        flags,
        signature,
        signature_length);
  } else {
    return CryptSignHashW(
        crypt_hash,
        key_spec,
        description_wide,
        flags,
        signature,
        signature_length);
  }
}

BOOL Win32_CryptVerifySignature(
    HCRYPTHASH crypt_hash,
    BYTE* signature,
    DWORD signature_length,
    HCRYPTKEY public_key,
    LPCSTR description_ansi,
    LPCWSTR description_wide,
    DWORD dwFlags) {
  if (Win9x_IsRunning()) {
    return CryptVerifySignatureA(
        crypt_hash,
        signature,
        signature_length,
        public_key,
        description_ansi,
        dwFlags);
  } else {
    return CryptVerifySignatureW(
        crypt_hash,
        signature,
        signature_length,
        public_key,
        description_wide,
        dwFlags);
  }
}
