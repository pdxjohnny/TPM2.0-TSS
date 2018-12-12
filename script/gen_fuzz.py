#!/usr/bin/env python3
import os
import argparse
import itertools

MAKEFILE_FUZZ = '''# SPDX-License-Identifier: BSD-2
# Copyright (c) 2018 Intel Corporation
# All rights reserved.

if ENABLE_TCTI_FUZZING
TESTS_FUZZ += %s
%s
endif # ENABLE_TCTI_FUZZING
'''
MAKEFILE_FUZZ_TARGET = '''
noinst_PROGRAMS += test/fuzz/%s
test_fuzz_%s_CFLAGS  = $(FUZZ_CFLAGS)
test_fuzz_%s_LDADD   = $(FUZZ_LDADD)
test_fuzz_%s_SOURCES = test/fuzz/main-sapi.c \\
    test/integration/sapi-test-options.c test/integration/sapi-context-util.c \\
    test/fuzz/%s.c'''
SYS_COMPLETE_TEMPLATE_HEADER = '''/* SPDX-License-Identifier: BSD-2 */
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
#include <stdarg.h>

#include <setjmp.h>

#include "tss2_mu.h"
#include "tss2_sys.h"
#include "tss2_tcti_device.h"

#include "tss2-tcti/tcti-common.h"
#include "tss2-tcti/tcti-device.h"

#define LOGMODULE fuzz
#include "tss2_tcti.h"
#include "util/log.h"
#include "test.h"
#include "test-options.h"
#include "context-util.h"
#include "tss2-sys/sysapi_util.h"
#include "tss2-tcti/tcti-fuzzing.h"

int
test_invoke (
        TSS2_SYS_CONTEXT *sysContext)'''
SYS_COMPLETE_TEMPLATE_NO_ARGS = SYS_COMPLETE_TEMPLATE_HEADER + '''
{
    %s (sysContext);

    return 0;
}
'''
SYS_COMPLETE_TEMPLATE_HAS_ARGS = SYS_COMPLETE_TEMPLATE_HEADER + '''
{
    %s

    %s (
        sysContext,
        %s
    );

    return 0;
}
'''
SYS_PREPARE_TEMPLATE_HAS_ARGS = SYS_COMPLETE_TEMPLATE_HEADER + '''
{
    int ret;
    %s

    ret = fuzz_fill (
        sysContext,
        %d,
        %s
    );
    if (ret) {
        return ret;
    }

    %s (
        sysContext,
        %s
    );

    return EXIT_SUCCESS;
}
'''

def gen_file(function):
    function_name = function.split('\n')[0]\
                            .replace('TSS2_RC', '')\
                            .replace('(', '')\
                            .strip()
    args = [arg.strip() \
            for arg in function[function.index('(') + 1:function.index(');')]\
            .split(',') \
            if not 'TSS2_SYS_CONTEXT' in arg]
    if '_Complete' in function_name:
        return gen_complete(function, function_name, args)
    if '_Prepare' in function_name:
        return gen_prepare(function, function_name, args)
    raise NotImplementedError('Unknown function type %r' % (function_name,))

def gen_complete(function, function_name, args):
    if not args:
        return function_name, SYS_COMPLETE_TEMPLATE_NO_ARGS % (function_name)
    arg_definitions = (';\n' + ' ' * 4).join([
        arg.replace('*', '') for arg in args]) + ';'
    arg_call = (',\n' + ' ' * 8).join([
        arg.replace('*', '&').split()[-1] for arg in args])
    return function_name, SYS_COMPLETE_TEMPLATE_HAS_ARGS % (arg_definitions,
                                                            function_name,
                                                            arg_call)

def gen_prepare(function, function_name, args):
    if not args:
        return function_name, None
    arg_definitions = (';\n' + ' ' * 4).join([
        arg.replace('*', '') for arg in args]) + ';'
    arg_call = (',\n' + ' ' * 8).join([
        arg.replace('*', '&').split()[-1] for arg in args])
    fill_fuzz_args = (',\n' + ' ' * 8).join([
        ('sizeof (%s), &%s' % \
                tuple([arg.replace('*', '').split()[-1]] * 2)) \
        for arg in args])
    return function_name, SYS_PREPARE_TEMPLATE_HAS_ARGS % (arg_definitions,
                                                           len(args) * 2,
                                                           fill_fuzz_args,
                                                           function_name,
                                                           arg_call)

def gen_files(header):
    current_function = ''
    with open(header, 'r') as header_fd:
        for line in header_fd:
            if '_Complete' in line or '_Prepare' in line:
                current_function = line
            elif current_function and ');' in line:
                current_function += line.rstrip()
                function_name, contents = gen_file(current_function)
                if contents is None:
                    print(function_name, 'takes no args, can\'t fuzz')
                    continue
                filepath = os.path.join('test', 'fuzz', function_name + '.c')
                with open(filepath, 'w') as fuzzer_fd:
                    fuzzer_fd.write(contents)
                yield function_name
                current_function = ''
            elif current_function:
                current_function += line

def main():
    parser = argparse.ArgumentParser(description='Generate libfuzzer for sapi')
    parser.add_argument('--header', default='include/tss2/tss2_sys.h',
            help='Header file to look in (default include/tss2/tss2_sys.h)')
    args = parser.parse_args()

    functions = list(gen_files(args.header))
    files = ' \\\n    '.join(['test/fuzz/%s' % (function) \
            for function in functions])
    targets = '\n'.join([MAKEFILE_FUZZ_TARGET % tuple(list(itertools.chain(\
            ([function] * 5)))) for function in functions])
    with open('Makefile-fuzz-generated.am', 'w') as makefile_fd:
        makefile_fd.write(MAKEFILE_FUZZ % (files, targets))

if __name__ == '__main__':
    main()
