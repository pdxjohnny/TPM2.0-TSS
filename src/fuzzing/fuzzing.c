/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "fuzzing.h"

fuzzing_t fuzzing = {
	.fd = {
		.logging = STDERR_FILENO,
		.response_lengths = -1,
		.response_payloads = -1,
	},
	.log = fuzzing_log,
	.log_response = fuzzing_log_response,
	.next = fuzzing_next_payload,
	.inspect = fuzzing_inspect,
	.argc = 0,
	.argv = NULL,
	.program_name = NULL,
};

static void fuzzing_grab_argv(int argc, char **argv, char **envp)
{
	(void) envp;
	fuzzing.argc = argc;
	fuzzing.argv = argv;
	fuzzing.program_name = strrchr (argv[0], '/') + 1;
    sprintf (
            fuzzing.filename.response_lengths,
            "lengths/%s",
            fuzzing.program_name);
    sprintf (
            fuzzing.filename.response_payloads,
            "testcases/%s/payloads",
            fuzzing.program_name);
}
__attribute__((section(".init_array")))
	void (*_fuzzing_grab_argv)(int, char **, char **) = &fuzzing_grab_argv;

static int
mkdir_if_not_exists (const char *dirname)
{
    struct stat stats;
    if (stat(dirname, &stats) == 0) {
        return 0;
    }
    return mkdir(dirname, 0700);
}

static void
mk_fuzzing_dirs ()
{
    char *dirname;

    if (mkdir_if_not_exists("lengths") == -1) {
        fuzzing.log (
             "Failed to make lengths/ directory: %s",
             strerror (errno));
        exit(1);
    }

    if (mkdir_if_not_exists("testcases") == -1) {
        fuzzing.log (
             "Failed to make testcases/ directory: %s",
             strerror (errno));
        exit(1);
    }

    if (asprintf (
                &dirname,
                "testcases/%s",
                fuzzing.program_name) == -1 || dirname == NULL) {
        fuzzing.log (
             "Failed to format payload directory string: %s",
             strerror (errno));
        exit(1);
    }
    if (mkdir_if_not_exists(dirname) == -1) {
        fuzzing.log (
             "Failed to make %s directory: %s",
             dirname,
             strerror (errno));
        free(dirname);
        exit(1);
    }
    free(dirname);
}

static inline void
log_to_file (
	int *fd,
	const char *filename,
	const uint8_t *buf,
	const size_t size)
{
	if (*fd == -1) {
        mk_fuzzing_dirs ();
		*fd  = open(filename, O_RDWR | O_CREAT, S_IRUSR);
		if (*fd < 0) {
			fuzzing.log (
				 "Failed to open file %s: %s",
				 filename,
				 strerror (errno));
			exit(1);
		}
	}
	if (write(*fd, buf, size) != (ssize_t)size) {
		fuzzing.log (
			 "Failed to write to file %s: %s",
			 filename,
			 strerror (errno));
		exit(1);
	}
}

void fuzzing_log(const char *fmt, ...) {
    char *buf;
    va_list ap;
    va_start(ap, fmt);
    if (asprintf (
                &buf,
                "[%s] %s\n",
                fuzzing.program_name,
                fmt) == -1) {
        return;
    }
	vdprintf(fuzzing.fd.logging, buf, ap);
    free(buf);
    va_end(ap);
}

void fuzzing_log_response(const uint8_t *buf, const size_t size) {
	uint32_t network_byte_order;

	if (strstr (fuzzing.argv[0], "tpm_startup") != NULL ||
            strstr (fuzzing.argv[0], "tpm_transientempty") != NULL ||
            strstr (fuzzing.argv[0], "test/unit/") != NULL) {
		return;
	}

	fuzzing.log (
            "Writing %zu bytes to fuzzing_*.log",
            size);

	network_byte_order = htonl(size);
	log_to_file (
		       &fuzzing.fd.response_lengths,
		       fuzzing.filename.response_lengths,
		       (const uint8_t *) &network_byte_order,
		       sizeof (network_byte_order));
	log_to_file (
		       &fuzzing.fd.response_payloads,
		       fuzzing.filename.response_payloads,
		       buf,
		       size);
}

size_t fuzzing_next_payload(uint8_t **buf) {
	size_t length = 0U;
	ssize_t bytes_read = 0U;
	uint32_t network_byte_order;

	switch (read (
		      fuzzing.fd.response_lengths,
		      &network_byte_order,
		      sizeof (network_byte_order))) {
	case 0:
		return 0U;
	case (sizeof (network_byte_order)):
		break;
	default:
		fuzzing.log (
			 "Failed to read payload length: %s",
			 strerror (errno));
		return 0U;
	}

	length = ntohl(network_byte_order);
	fuzzing.log (
		 "Reading fuzzing payload of length: %zu",
		 length);

	*buf = calloc(sizeof (buf), length);
	if (*buf == NULL) {
		fuzzing.log (
			 "Failed allocate %zu bytes for payload: %s",
			 length, strerror (errno));
		return 0U;
	}

	if ((bytes_read = read (
		  fuzzing.fd.response_payloads,
		  *buf,
		  length)) != (ssize_t)length) {
		fuzzing.log (
			 "Failed to read payload (%zu != %zd): %s",
			 length,
			 bytes_read,
			 strerror (errno));
		return 0U;
	}

	return length;
}


void fuzzing_inspect(
                     int fd)
{
    uint8_t *buf;
    size_t length;

    while ((length = fuzzing.next(&buf)) > 0U) {
        for (size_t i = 0; i < length; ++i) {
            if (i != 0 && i != 1 && i % 8 == 0) {
                dprintf (fd, "\n");
            } else if (i != 0 && i != 1 && i % 2 == 0) {
                dprintf (fd, " ");
            }
            dprintf (
                     fd,
                     "%02hhx",
                     (unsigned char)(((unsigned int)buf[i]) & 0xFF));
        }
        dprintf (fd, "\n");
        free(buf);
    }
}
