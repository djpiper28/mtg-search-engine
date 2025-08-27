#pragma once
/// Writes binary in my arbitary format. Strings are pascal strings when
/// written, then c strings when read. Simple as.

/// All return 1 on success, 0 on fail.
#include <time.h>
#include <stdio.h>

int mse_write_float(FILE *f, float d);
int mse_read_float(FILE *f, float *d);

int mse_write_int(FILE *f, int i);
int mse_read_int(FILE *f, int *i);

int mse_write_size_t(FILE *f, size_t i);
int mse_read_size_t(FILE *f, size_t *i);

int mse_write_str(FILE *f, char *str);
int mse_read_str(FILE *f, char **str);

int mse_write_tm(FILE *f, struct tm t);
int mse_read_tm(FILE *f, struct tm *t);

/// strtod wrapper
int mse_to_float(char *input, float *ret);

char *mse_to_lower(const char *input);
