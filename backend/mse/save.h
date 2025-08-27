#pragma once
#include "mse_formats.h"
#include "./mtg_json.h"
#include "./thread_pool.h"
#include <stdio.h>

#define MSE_CARDS_FILE_NAME "cards.data"
// Change the left-most magic number when the format changes
//                                    v this one
#define MSE_BINARY_VERSION ((size_t) (4ul | (((size_t) MSE_FORMAT_MAGIC_NUMBER) << 32)))

/// Writes all cards and sets to f
int mse_write_cards(FILE *f, mse_all_printings_cards_t *cards);

/// Reads all cards and sets to f, without indexing, used in tests
int mse_read_cards(FILE *f, mse_all_printings_cards_t *cards);

/// Gets and indexes all cards from MSE_CARDS_FILE_NAME
int mse_get_cards_from_file(mse_all_printings_cards_t *cards, mse_thread_pool_t *pool);
