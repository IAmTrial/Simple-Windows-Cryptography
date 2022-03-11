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

#include "option.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "generate.h"
#include "help.h"
#include "sign.h"
#include "verify.h"

static int Option_Compare(
    const struct Option* entry1,
    const struct Option* entry2) {
  return wcscmp(entry1->option, entry2->option);
}

static int Option_CompareAsVoid(const void* entry1, const void* entry2) {
  return Option_Compare(entry1, entry2);
}

static const struct Option kSortedOptionTable[] = {
  {
    GENERATE_TEXT,
    5,
    &Help_PrintGenerateOption,
    &Cryptography_GeneratePubPrivKey
  }, {
    SIGN_TEXT,
    6,
    &Help_PrintSignOption,
    &Cryptography_SignFile
  }, {
    VERIFY_TEXT,
    6,
    &Help_PrintVerifyOption,
    &Cryptography_VerifySignature
  },
};

enum {
  kSortedOptionTableCount = sizeof(kSortedOptionTable)
      / sizeof(kSortedOptionTable[0]),
};

/**
 * External
 */

const struct Option* Option_SearchTable(const wchar_t* option) {
  const struct Option* search_result;

  search_result = bsearch(
      &option,
      kSortedOptionTable,
      kSortedOptionTableCount,
      sizeof(kSortedOptionTable[0]),
      &Option_CompareAsVoid);

  return search_result;
}
