/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 */
#ifndef FUZZING_H
#define FUZZING_H
#include <inttypes.h>

#define FUZZING_PREFIX "/tmp/tpm2-tss/fuzzing"

#ifdef __cplusplus
extern "C" {
#endif

void fuzzing_log(const char *fmt, ...);
void fuzzing_log_response(const uint8_t *buf, const size_t size);
size_t fuzzing_next_payload(uint8_t **buf);
void fuzzing_inspect(int fd);

typedef struct {
	struct {
		int logging;
		int response_lengths;
		int response_payloads;
	} fd;
	struct {
		char response_lengths[512];
		char response_payloads[512];
	} filename;
	void (*log)(const char *fmt, ...);
	void (*log_response)(const uint8_t *buf, const size_t size);
	size_t (*next)(uint8_t **buf);
	void (*inspect)(int fd);
	int argc;
	char **argv;
	char *program_name;
} fuzzing_t;

extern fuzzing_t fuzzing;

#ifdef __cplusplus
}
#endif
#endif /* FUZZING_H */
