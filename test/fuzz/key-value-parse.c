/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2017-2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "util/key-value-parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    bool ret;
    char test_str[Size];
    key_value_t key_value = KEY_VALUE_INIT;

    memcpy(test_str, Data, Size);

    ret = parse_key_value (test_str, &key_value);
    return 0;  // Non-zero return values are reserved for future use.
}
