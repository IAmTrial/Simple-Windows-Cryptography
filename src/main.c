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

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "help.h"
#include "option.h"

int wmain(int argc, wchar_t** argv) {
  int is_option_action_success;

  const struct Option* option;

  if (argc < 2) {
    Help_PrintGeneral();
    getchar();
    return 0;
  }

  option = Option_SearchTable(argv[1]);
  if (option == NULL) {
    Help_PrintGeneral();
    getchar();
    return 0;
  }

  if (argc < option->min_args) {
    option->help_func();
    getchar();
    return 0;
  }

  is_option_action_success = option->action_func(argc, argv);
  if (!is_option_action_success) {
    option->help_func();
    getchar();
    return 0;
  }

  return 0;
}
