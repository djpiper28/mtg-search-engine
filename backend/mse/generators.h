#pragma once
#include <stddef.h>
#include "./avl_tree.h"
#include "./mtg_json.h"
#include "./search.h"

/// An enum with all of the generator types (what to generate a set off of)
typedef enum mse_set_generator_type_t {
    MSE_SET_GENERATOR_COLOUR,
    MSE_SET_GENERATOR_COLOUR_IDENTITY,
    /// Regex or trie lookup
    MSE_SET_GENERATOR_NAME,
    /// Regex or substr matching
    MSE_SET_GENERATOR_ORACLE_TEXT,
    /// Cards in a set
    MSE_SET_GENERATOR_SET,
    MSE_SET_GENERATOR_POWER,
    MSE_SET_GENERATOR_CMC,
    MSE_SET_GENERATOR_LOYALTY,
    MSE_SET_GENERATOR_TOUGHNESS,
    MSE_SET_GENERATOR_TYPE,
    // Card legalities
    MSE_SET_GENERATOR_BANNED,
    MSE_SET_GENERATOR_LEGAL,
    MSE_SET_GENERATOR_RESTRICTED,
    MSE_SET_GENERATOR_UNPLAYABLE,
} mse_set_generator_type_t;

/// An enum with all of the operators for a set generator
typedef enum mse_set_generator_operator_t {
    /// :
    MSE_SET_GENERATOR_OP_INCLUDES,
    /// =
    MSE_SET_GENERATOR_OP_EQUALS,
    /// <
    MSE_SET_GENERATOR_OP_LT,
    /// <=
    MSE_SET_GENERATOR_OP_LT_INC,
    /// >
    MSE_SET_GENERATOR_OP_GT,
    /// >=
    MSE_SET_GENERATOR_OP_GT_INC
} mse_set_generator_operator_t;

/// The set generator and its information, use the mse_init_set_generator function
typedef struct mse_set_generator_t {
    mse_set_generator_type_t generator_type;
    mse_set_generator_operator_t generator_op;
    char *argument;
    /// Whether to negate the operation, this is an optional parameter
    /// so I added it here instead of the constructor for compatibility
    /// (laziness) reasons.
    int negate;
} mse_set_generator_t;

/// Runs validation that the operation is defined for the given type
/// Also copies the argument string, len is the string length of the argument
int mse_init_set_generator(mse_set_generator_t *ret,
                           mse_set_generator_type_t gen_type,
                           mse_set_generator_operator_t op_type,
                           char *argument,
                           size_t len);

void mse_free_set_generator(mse_set_generator_t *gen);

/// Helper function used in init to check that that the set can be generated
int __mse_validate_generator_op_combo(mse_set_generator_type_t gen_type,
                                      mse_set_generator_operator_t op_type);

int mse_generate_set(mse_set_generator_t *gen,
                     mse_search_intermediate_t *res,
                     mse_all_printings_cards_t *cards);

/// String to generator type
int mse_gen_type(char *str, mse_set_generator_type_t *ret);
