#include <stdlib.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "sapi/tpm20.h"
#include "sysapi_util.h"
#include "tcti/tcti_socket.h"
#include "test_utils/syscontext.h"

TSS2_ABI_VERSION abiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

/**
 * Sends PlatformCommands to power cycle the TPM
 */
TSS2_RC TpmReset()
{
    TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
    TSS2_RC rval = TSS2_RC_SUCCESS;

    rval = (TSS2_RC)PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );
    if( rval == TSS2_RC_SUCCESS )
    {
        rval = (TSS2_RC)PlatformCommand( resMgrTctiContext, MS_SIM_POWER_ON );
    }
    return rval;
}

/**
 * Sends PlatformCommands to power cycle the TPM
 */
static void
Tss2_Sys_Startup_PowerCycle_unit (void **state)
{
    TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
    // Cycle power using simulator interface.
    TSS2_RC rval = PlatformCommand(resMgrTctiContext, MS_SIM_POWER_OFF);
    assert_int_equal(rval, TPM_RC_SUCCESS);
    rval = PlatformCommand(resMgrTctiContext, MS_SIM_POWER_ON);
    assert_int_equal(rval, TPM_RC_SUCCESS);
}

/**
 * Makes sure startup is successful
 */
static void
Tss2_Sys_Startup_Success_unit (void **state)
{
    TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
    TSS2_SYS_CONTEXT *sysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    // First must do TPM reset.
    UINT32 rval = TpmReset();
    assert_int_equal(rval, TPM_RC_SUCCESS);

    // This one should pass.
    rval = Tss2_Sys_Startup(sysContext, TPM_SU_CLEAR);
    assert_int_equal(rval, TPM_RC_SUCCESS);
}

/**
 * Ensure Tss2_Sys_Startup fails properly
 */
static void
Tss2_Sys_Startup_Fail_unit (void **state)
{
    TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
    TSS2_SYS_CONTEXT *sysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    // First must do TPM reset.
    UINT32 rval = TpmReset();
    assert_int_equal(rval, TPM_RC_SUCCESS);

    // This one should fail.
    rval = Tss2_Sys_Startup(sysContext, TPM_SU_CLEAR);
    assert_int_equal(rval, TPM_RC_INITIALIZE);
}

/**
 * Synchronous startup
 */
static void
Tss2_Sys_Startup_Sync_unit (void **state)
{
    TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
    TSS2_SYS_CONTEXT *sysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    // First must do TPM reset.
    UINT32 rval = TpmReset();
    assert_int_equal(rval, TPM_RC_SUCCESS);

    // Now test the syncronous, non-one-call interface.
    rval = Tss2_Sys_Startup_Prepare(sysContext, TPM_SU_CLEAR);
    assert_int_equal(rval, TPM_RC_INITIALIZE);

    // Execute the command syncronously.
    rval = Tss2_Sys_Execute(sysContext);
    assert_int_equal(rval, TPM_RC_INITIALIZE);
}

/**
 * Asynchronous startup
 */
static void
Tss2_Sys_Startup_Async_unit (void **state)
{
    TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
    TSS2_SYS_CONTEXT *sysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    // First must do TPM reset.
    UINT32 rval = TpmReset();
    assert_int_equal(rval, TPM_RC_SUCCESS);

    // Now test the asyncronous, non-one-call interface.
    rval = Tss2_Sys_Startup_Prepare(sysContext, TPM_SU_CLEAR);
    assert_int_equal(rval, TPM_RC_SUCCESS);

    // Execute the command asyncronously.
    rval = Tss2_Sys_ExecuteAsync(sysContext);
    assert_int_equal(rval, TPM_RC_SUCCESS);

    // Get the command response. Wait a maximum of 20ms for response.
    rval = Tss2_Sys_ExecuteFinish(sysContext, TSS2_TCTI_TIMEOUT_BLOCK);
    assert_int_equal(rval, TPM_RC_SUCCESS);
}

int
main (int   argc,
      char *argv[])
{
    const UnitTest tests [] = {
        unit_test (Tss2_Sys_Startup_PowerCycle_unit),
        unit_test (Tss2_Sys_Startup_Success_unit),
        unit_test (Tss2_Sys_Startup_Fail_unit),
        unit_test (Tss2_Sys_Startup_Sync_unit),
        unit_test (Tss2_Sys_Startup_Async_unit),
    };
    return run_tests (tests);
}
