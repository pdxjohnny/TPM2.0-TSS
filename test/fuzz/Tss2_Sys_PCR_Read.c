/* SPDX-License-Identifier: BSD-2 */
/***********************************************************************
 * Copyright (c) 2018, Intel Corporation
 *
 * All rights reserved.
 ***********************************************************************/
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_mu.h"
#include "tss2_sys.h"
#include "tss2_tcti_device.h"

#include "tss2-tcti/tcti-common.h"
#include "tss2-tcti/tcti-device.h"

int
test_invoke (
        TSS2_SYS_CONTEXT *sysContext)
{
    UINT32 pcrUpdateCounter;
    TPML_PCR_SELECTION pcrSelectionOut;
    TPML_DIGEST pcrValues;

    Tss2_Sys_PCR_Read_Complete (
        sysContext,
        &pcrUpdateCounter,
        &pcrSelectionOut,
        &pcrValues
    );

    return 0;
}
