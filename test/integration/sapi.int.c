#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"

#define INIT_SIMPLE_TPM2B_SIZE( type ) (type).t.size = sizeof( type ) - 2
#define CheckPassed(X) if (X != TSS2_RC_SUCCESS) {\
  print_fail("SAPI Test FAILED! Response Code : %x", X); }

#define CheckFailed(X, Y) if (X != Y) {\
  print_fail("SAPI Test FAILED! Response Code : %x should be %x", X, Y); }
/**
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPM2B_MAX_BUFFER    outData = { { MAX_DIGEST_BUFFER, } };
    TPM_RC              testResult;
    TSS2_SYS_CONTEXT    *testSysContext;
    TPM2B_PUBLIC        outPublic;
    TPM2B_NAME          name;
    TPM2B_NAME          qualifiedName;
    UINT8               commandCode[4];
    size_t				rpBufferUsedSize;
	const uint8_t 		*rpBuffer;
	const uint8_t 		goodRpBuffer[] = { 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
                                       0x01, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x40 };
    TPMI_YES_NO         moreData;
    TPMS_CAPABILITY_DATA	capabilityData;
    int                 rpBufferError = 0;
    unsigned int        i;
    UINT32              savedRspSize;

    print_log("SAPI tests started.");

    //
    // First test the one-call interface.
    //
    rc = Tss2_Sys_GetTestResult( sapi_context, 0, &outData, &testResult, 0 );
    CheckPassed(rc);

    // Check for BAD_SEQUENCE error.
    rc = Tss2_Sys_ExecuteAsync( sapi_context );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #2

    // Check for BAD_SEQUENCE error.
    rc = Tss2_Sys_Execute( sapi_context );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #3

    //
    // Now test the syncronous, non-one-call interface.
    //
    rc = Tss2_Sys_GetTestResult_Prepare( sapi_context );
    CheckPassed(rc); // #4

    // Check for BAD_REFERENCE error.
    rc = Tss2_Sys_Execute( 0 );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #5

    // Execute the command syncronously.
    rc = Tss2_Sys_Execute( sapi_context );
    CheckPassed(rc); // #6

    // Check for BAD_SEQUENCE error.
    rc = Tss2_Sys_Execute( sapi_context );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #7

    // Check for BAD_SEQUENCE error.
    rc = Tss2_Sys_ExecuteAsync( sapi_context );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #8

    // Get the command results
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rc = Tss2_Sys_GetTestResult_Complete( sapi_context, &outData, &testResult );
    CheckPassed(rc); // #9

    //
    // Now test the asyncronous, non-one-call interface.
    //
    rc = Tss2_Sys_GetTestResult_Prepare( sapi_context );
    CheckPassed(rc); // #10

    // Test XXXX_Complete for bad sequence:  after _Prepare
    // and before ExecuteFinish
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rc = Tss2_Sys_GetTestResult_Complete( sapi_context, &outData, &testResult );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #11

    // Check for BAD_REFERENCE error.
    rc = Tss2_Sys_ExecuteAsync( 0 );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #12

    // Test ExecuteFinish for BAD_SEQUENCE
    rc = Tss2_Sys_ExecuteFinish( sapi_context, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #13

    // Execute the command asyncronously.
    rc = Tss2_Sys_ExecuteAsync( sapi_context );
    CheckPassed(rc); // #14

    // Check for BAD_SEQUENCE error.
    rc = Tss2_Sys_ExecuteAsync( sapi_context );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #15

    // Check for BAD_SEQUENCE error.
    rc = Tss2_Sys_Execute( sapi_context );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #16

    // Test ExecuteFinish for BAD_REFERENCE
    rc = Tss2_Sys_ExecuteFinish( 0, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #17

    // Test XXXX_Complete for bad sequence:  after _Prepare
    // and before ExecuteFinish
    rc = Tss2_Sys_GetTestResult_Complete( sapi_context, &outData, &testResult );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #18

    // Get the command response. Wait a maximum of 20ms
    // for response.
    rc = Tss2_Sys_ExecuteFinish( sapi_context, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed(rc); // #19

    rc = Tss2_Sys_ExecuteFinish( sapi_context, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #20

    // Check for BAD_SEQUENCE error.
    rc = Tss2_Sys_ExecuteAsync( sapi_context );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #21

    // Check for BAD_SEQUENCE error.
    rc = Tss2_Sys_Execute( sapi_context );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #22

    // Test _Complete for bad reference cases.
    rc = Tss2_Sys_GetTestResult_Complete( 0, &outData, &testResult );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #23

    // Get the command results
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rc = Tss2_Sys_GetTestResult_Complete( sapi_context, &outData, &testResult );
    CheckPassed(rc); // #24

    rc = Tss2_Sys_GetTctiContext (sapi_context, &testSysContext);
    CheckPassed(rc);

    // Test GetCommandCode for bad sequence
    rc = Tss2_Sys_GetCommandCode( testSysContext, &commandCode );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #25

    rc = Tss2_Sys_GetRpBuffer( testSysContext, &rpBufferUsedSize, &rpBuffer );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #26

    TeardownSysContext( &testSysContext );

    rc = Tss2_Sys_ReadPublic_Prepare( sapi_context, handle2048rsa );
    CheckPassed(rc); // #27

    // Execute the command syncronously.
    rc = Tss2_Sys_ExecuteAsync( sapi_context );
    CheckPassed( rc ); // #28

    // Test _Complete for bad sequence case when ExecuteFinish has never
    // been done on a context.
    INIT_SIMPLE_TPM2B_SIZE( name );
    rc = Tss2_Sys_ReadPublic_Complete( sapi_context, &outPublic, &name, &qualifiedName );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #29

    rc = Tss2_Sys_ExecuteFinish( sapi_context, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckPassed( rc ); // #30

    rc = Tss2_Sys_ExecuteFinish( sapi_context, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #31

    rc = Tss2_Sys_ReadPublic_Prepare( sapi_context, handle2048rsa );
    CheckPassed(rc); // #32

    rc = Tss2_Sys_ExecuteFinish( sapi_context, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #33

    rc = Tss2_Sys_ReadPublic_Prepare( sapi_context, handle2048rsa );
    CheckPassed(rc); // #34

    // Execute the command syncronously.
    rc = Tss2_Sys_Execute( sapi_context );
    CheckPassed( rc ); // #35

	outPublic.t.size = name.t.size = qualifiedName.t.size = 0;
	rc = Tss2_Sys_ReadPublic( sapi_context, handle2048rsa, 0,
            &outPublic, 0, 0, 0 );
    CheckPassed( rc ); // #36

    // Check case of ExecuteFinish receving TPM error code.
    // Subsequent _Complete call should fail with SEQUENCE error.
    rc = TpmReset();
    CheckPassed(rc); // #37

    rc = Tss2_Sys_GetCapability_Prepare( sapi_context,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_ACTIVE_SESSIONS_MAX,
            1 );
    CheckPassed(rc); // #38

    // Execute the command asyncronously.
    rc = Tss2_Sys_ExecuteAsync( sapi_context );
    CheckPassed(rc); // #39

    // Get the command response. Wait a maximum of 20ms
    // for response.
    rc = Tss2_Sys_ExecuteFinish( sapi_context, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rc, TPM_RC_INITIALIZE ); // #40

    // Test _Complete for case when ExecuteFinish had an error.
    rc = Tss2_Sys_GetCapability_Complete( sapi_context, 0, 0 );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #41

    rc = Tss2_Sys_Startup( sapi_context, TPM_SU_CLEAR );
    CheckPassed(rc); // #42

    rc = Tss2_Sys_GetRpBuffer( 0, &rpBufferUsedSize, &rpBuffer );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #43

    rc = Tss2_Sys_GetRpBuffer( sapi_context, 0, &rpBuffer );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #44

    rc = Tss2_Sys_GetRpBuffer( sapi_context, &rpBufferUsedSize, 0 );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #45

    rc = Tss2_Sys_GetRpBuffer( sapi_context, &rpBufferUsedSize, &rpBuffer );
    CheckPassed( rc ); // #46

    // Now test case for ExecuteFinish where TPM returns
    // an error.  ExecuteFinish should return same error
    // as TPM.
    rc = Tss2_Sys_Startup_Prepare( sapi_context, TPM_SU_CLEAR );
    CheckPassed(rc); // #47

    // Execute the command ayncronously.
    rc = Tss2_Sys_ExecuteAsync( sapi_context );
    CheckPassed( rc ); // #48

    rc = Tss2_Sys_Startup( sapi_context, TPM_SU_CLEAR );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #49

    rc = Tss2_Sys_ExecuteFinish( sapi_context, TSS2_TCTI_TIMEOUT_BLOCK );
    CheckFailed( rc, TPM_RC_INITIALIZE ); // #50

    // Now test case for ExecuteFinish where TPM returns
    // an error.  ExecuteFinish should return same error
    // as TPM.
    rc = Tss2_Sys_Startup_Prepare( sapi_context, TPM_SU_CLEAR );
    CheckPassed(rc); // #51

    rc = Tss2_Sys_GetRpBuffer( sapi_context, &rpBufferUsedSize, &rpBuffer );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #52

    // Execute the command ayncronously.
    rc = Tss2_Sys_Execute( sapi_context );
    CheckFailed( rc, TPM_RC_INITIALIZE ); // #53

    rc = Tss2_Sys_GetRpBuffer( sapi_context, &rpBufferUsedSize, &rpBuffer );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #54

    // Test one-call for null sapi_context pointer.
    rc = Tss2_Sys_Startup( 0, TPM_SU_CLEAR );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #55

    // Test one-call for NULL input parameter that should be a
    // pointer.
    rc = Tss2_Sys_Create( testSysContext, 0xffffffff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #56

    // Test GetCommandCode for bad reference
    rc = Tss2_Sys_GetCommandCode( 0, &commandCode );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #57

    rc = Tss2_Sys_GetCommandCode( sapi_context, 0 );
    CheckFailed( rc, TSS2_SYS_RC_BAD_REFERENCE ); // #58

    //
    // Test GetRpBuffer for case of no response params or handles.
    //
    rc = Tss2_Sys_Shutdown( sapi_context, 0, TPM_SU_STATE, 0 );
    CheckPassed( rc ); // #59

    rc = Tss2_Sys_GetRpBuffer( sapi_context, &rpBufferUsedSize, &rpBuffer );
    CheckPassed( rc ); // #60

    if( rpBufferUsedSize != 0 )
    {
        print_log("ERROR!!  Tss2_Sys_GetRpBuffer returned non-zero size for command that returns no handles or parameters");
        Cleanup();
    }

    //
    // Test GetRpBuffer for case of response params.
    //
    rc = Tss2_Sys_GetCapability( sapi_context, 0,
            TPM_CAP_TPM_PROPERTIES, TPM_PT_ACTIVE_SESSIONS_MAX,
            1, &moreData, &capabilityData, 0 );
    CheckPassed(rc); // #61

    rc = Tss2_Sys_GetRpBuffer( sapi_context, &rpBufferUsedSize, &rpBuffer );
    CheckPassed( rc ); // #62

    if( rpBufferUsedSize != 17 )
    {
        print_log("ERROR!!  Tss2_Sys_GetRpBuffer returned wrong size for command that returns handles and/or parameters");
        Cleanup();
    }

    // Now compare RP buffer to what it should be
    for( i = 0; i < rpBufferUsedSize; i++ )
    {
        if( rpBuffer[i] != goodRpBuffer[i] )
        {
            rpBufferError = 1;
            break;
        }
    }

    if( rpBufferError )
    {
        print_log("ERROR!!  Tss2_Sys_GetRpBuffer returned wrong rpBuffer contents");
        /*
        DebugPrintf( NO_PREFIX, "\nERROR!!  Tss2_Sys_GetRpBuffer returned wrong rpBuffer contents:\nrpBuffer was: \n\t" );
        DebugPrintBuffer( NO_PREFIX, (UINT8 *)&rpBuffer, rpBufferUsedSize );
        DebugPrintf( NO_PREFIX, "\nrpBuffer s/b:\n\t" );
        DebugPrintBuffer( NO_PREFIX, (UINT8 *)&(goodRpBuffer[0]), rpBufferUsedSize );
        */
        Cleanup();
    }

    TeardownSysContext( &testSysContext );

    rc = Tss2_Sys_GetTestResult_Prepare( sapi_context );
    CheckPassed(rc); // #63

    // Execute the command syncronously.
    rc = Tss2_Sys_Execute( sapi_context );
    CheckPassed(rc); // #64

    // Get the command results
    // NOTE: this test modifies internal fields of the sapi_context structure.
    // DON'T DO THIS IN REAL APPS!!
    savedRspSize = BE_TO_HOST_32(((TPM20_Header_Out *)(SYS_CONTEXT->tpmOutBuffPtr))->responseSize);
    ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr )  )->responseSize = 4097;
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rc = Tss2_Sys_GetTestResult_Complete( sapi_context, &outData, &testResult );
    ( (TPM20_Header_Out *)( SYS_CONTEXT->tpmOutBuffPtr )  )->responseSize = savedRspSize;
    CheckFailed( rc, TSS2_SYS_RC_MALFORMED_RESPONSE ); // #65

    // NOTE: this test case is kind of bogus--no application would ever do this
    // since apps can't change the responseSize after TPM has returned the response.
    // ONce the MALFOMED_RESPONSE occurs, there's no way to recover the response data.
    INIT_SIMPLE_TPM2B_SIZE( outData );
    rc = Tss2_Sys_GetTestResult_Complete( sapi_context, &outData, &testResult );
    CheckFailed( rc, TSS2_SYS_RC_BAD_SEQUENCE ); // #66

    print_log("SAPI Test Passed!");
    return 0;
}
