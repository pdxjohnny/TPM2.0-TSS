/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
 *******************************************************************************/

#include "tss2_esys.h"

#include "esys_iutil.h"
#define LOGMODULE test
#include "util/log.h"

/*
 * This test is intended to test the definition of a bit field in NV ram and to
 * test the ESAPI NV_SetBits function.
 */

int
test_invoke_esapi(ESYS_CONTEXT * esys_context)
{
    uint32_t r = 0;
#ifdef TEST_SESSION
    ESYS_TR session;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    memset(&sessionAttributes, 0, sizeof sessionAttributes);

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    goto_if_error(r, "Error: During initialization of session", error);
#endif /* TEST_SESSION */

    ESYS_TR nvHandle_handle;
    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD |
                TPM2_NT_BITS << TPMA_NV_TPM2_NT_SHIFT
                ),
            .authPolicy = {
                 .size = 0,
                 .buffer = {},
             },
            .dataSize = 8,
        }
    };

    r = Esys_NV_DefineSpace(esys_context,
                            ESYS_TR_RH_OWNER,
#ifdef TEST_SESSION
                            session,
#else
                            ESYS_TR_PASSWORD,
#endif
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &auth,
                            &publicInfo,
                            &nvHandle_handle);

    goto_if_error(r, "Error esys define nv space", error);

    TPM2B_NV_PUBLIC *nvPublic;
    TPM2B_NAME *nvName;

    r = Esys_NV_ReadPublic(esys_context,
                           nvHandle_handle,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &nvPublic,
                           &nvName);
    goto_if_error(r, "Error: nv read public", error);

    RSRC_NODE_T *nvHandleNode;

    r = esys_GetResourceObject(esys_context, nvHandle_handle, &nvHandleNode);
    goto_if_error(r, "Error: nv get resource object", error);

    if (nvName->size != nvHandleNode->rsrc.name.size ||
        memcmp(&nvName->name, &nvHandleNode->rsrc.name.name, nvName->size) != 0) {
        LOG_ERROR("Error: define space name not equal");
        goto error;
    }

    UINT64 bits = 0x0102030405060708;

    r = Esys_NV_SetBits(esys_context,
                        nvHandle_handle,
                        nvHandle_handle,
#ifdef TEST_SESSION
                        session,
#else
                        ESYS_TR_PASSWORD,
#endif
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        bits);

    goto_if_error(r, "Error esys nv write", error);

    r = Esys_NV_ReadPublic(esys_context,
                           nvHandle_handle,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &nvPublic,
                           &nvName);
    goto_if_error(r, "Error: nv read public", error);

    r = esys_GetResourceObject(esys_context, nvHandle_handle, &nvHandleNode);
    goto_if_error(r, "Error: nv get resource object", error);

    if (nvName->size != nvHandleNode->rsrc.name.size ||
        memcmp(&nvName->name, &nvHandleNode->rsrc.name.name, nvName->size) != 0) {
        LOG_ERROR("Error: nv write name not equal");
        goto error;
    }

    TPM2B_MAX_NV_BUFFER *nv_test_data;

    r = Esys_NV_Read(esys_context,
                     nvHandle_handle,
                     nvHandle_handle,
#ifdef TEST_SESSION
                     session,
#else
                     ESYS_TR_PASSWORD,
#endif
                     ESYS_TR_NONE,
                     ESYS_TR_NONE,
                     8,
                     0,
                     &nv_test_data);

    goto_if_error(r, "Error esys nv read", error);

    r = Esys_NV_ReadPublic(esys_context,
                           nvHandle_handle,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &nvPublic,
                           &nvName);
    goto_if_error(r, "Error: nv read public", error);

    r = esys_GetResourceObject(esys_context, nvHandle_handle, &nvHandleNode);
    goto_if_error(r, "Error: nv get resource object", error);

    if (nvName->size != nvHandleNode->rsrc.name.size ||
        memcmp(&nvName->name, &nvHandleNode->rsrc.name.name, nvName->size) != 0) {
        LOG_ERROR("Error: nv read name not equal");
        goto error;
    }

    r = Esys_NV_UndefineSpace(esys_context,
                              ESYS_TR_RH_OWNER,
                              nvHandle_handle,
#ifdef TEST_SESSION
                              session,
#else
                              ESYS_TR_PASSWORD,
#endif
                              ESYS_TR_NONE,
                              ESYS_TR_NONE
                              );
    goto_if_error(r, "Error: NV_UndefineSpace", error);

#ifdef TEST_SESSION
    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error: FlushContext", error);
#endif

    return 0;

 error:
    return 1;
}
