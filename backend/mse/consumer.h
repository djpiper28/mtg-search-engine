#pragma once
#include <stddef.h>
#include "./avl_tree.h"
#include "./mtg_json.h"
#include "./search.h"

/// The type of the consumer
typedef enum mse_set_consumer_type_t {
    /// Oracle text matching
    MSE_SET_CONSUMER_ORACLE,
    /// Name text matching (defined for regex only)
    MSE_SET_CONSUMER_NAME,
    /// Negation of a set
    MSE_SET_CONSUMER_NEGATE
} mse_set_consumer_type_t;

/// The set generator and its information
typedef struct mse_set_consumer_t {
    mse_set_consumer_type_t generator_type;
    char *argument;
} mse_set_consumer_t;

/// Runs validation that the operation is defined for the given type
/// Also copies the argument string, len is the string length of the argument
int mse_init_set_consumer(mse_set_consumer_t *ret,
                          mse_set_consumer_type_t gen_type,
                          char *argument,
                          size_t len);

void mse_free_set_consumer(mse_set_consumer_t *gen);

int mse_consume_set(mse_set_consumer_t *gen,
                    mse_search_intermediate_t *res,
                    mse_all_printings_cards_t *cards,
                    mse_search_intermediate_t *child);
