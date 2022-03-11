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

#ifndef SWINCRYPT_OPTION_H_
#define SWINCRYPT_OPTION_H_

#include <stddef.h>
#include <wchar.h>

#define GENERATE_TEXT L"generate"
#define SIGN_TEXT L"sign" 
#define VERIFY_TEXT L"verify"

struct Option {
  const wchar_t* option;
  int min_args;
  void (*help_func)(void);
  int (*action_func)(int argc, wchar_t** argv);
};

const struct Option* Option_SearchTable(const wchar_t* option);

#endif /* SWINCRYPT_OPTION_H_ */
