/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 */

#ifndef TCTI_FUZZING_H
#define TCTI_FUZZING_H

#include <limits.h>

#include "tcti-common.h"
#include "util/io.h"

#define TCTI_FUZZING_MAGIC 0x66757a7a696e6700ULL

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    const uint8_t *data;
    size_t size;
} TSS2_TCTI_FUZZING_CONTEXT;

TSS2_TCTI_FUZZING_CONTEXT*
tcti_fuzzing_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx);

#endif /* TCTI_FUZZING_H */
