#include "./generator_float_fields.h"
#include "./card.h"
#include "./avl_tree.h"
#include "./io_utils.h"
#include "../testing_h/testing.h"
#include <string.h>

#define MSE_GENERATOR_FIELD_GENERATOR(fname) \
static int __mse_generate_set_##fname##_eq(mse_set_generator_t *gen, \
                                       mse_search_intermediate_t *res, \
                                       mse_all_printings_cards_t *cards, \
                                       float arg) \
{ \
    /* Prepare the bounds of the search */ \
    mse_card_t lower, upper; \
    memset(&lower, 0, sizeof(lower)); \
    upper = lower; \
 \
    lower.id = mse_min_uuid(); \
    upper.id = mse_max_uuid(); \
    lower.fname = upper.fname = arg; \
    /* Search the tree */ \
    mse_avl_tree_node_t *node = NULL; \
    ASSERT(mse_tree_lookup_2(cards->indexes.card_##fname##_tree, &node, (void *) &lower, (void *) &upper)); \
    *res = mse_init_search_intermediate_tree(node, 0); \
    return 1; \
} \
 \
static int __mse_generate_set_##fname##_ne(mse_set_generator_t *gen, \
                                       mse_search_intermediate_t *res, \
                                       mse_all_printings_cards_t *cards, \
                                       float arg) \
{ \
    ASSERT(__mse_generate_set_##fname##_eq(gen, res, cards, arg)); \
 \
    if (gen->negate) { \
        mse_search_intermediate_t tmp; \
        memset(&tmp, 0, sizeof(tmp)); \
 \
        ASSERT(mse_set_negate(&tmp, cards, res)); \
        mse_free_search_intermediate(res); \
        *res = tmp; \
    } \
    return 1; \
} \
 \
static int __mse_generate_set_##fname##_lt(mse_set_generator_t *gen, \
                                       mse_search_intermediate_t *res, \
                                       mse_all_printings_cards_t *cards, \
                                       float arg) \
{ \
    /* Prepare the bounds of the search */ \
    mse_card_t lower; \
    memset(&lower, 0, sizeof(lower)); \
    lower.id = mse_min_uuid(); \
 \
    lower.fname = arg; \
 \
    /* Search the tree */ \
    mse_avl_tree_node_t *node = NULL; \
    ASSERT(mse_tree_lookup(cards->indexes.card_##fname##_tree, &node, 1, (void *) &lower)); \
    *res = mse_init_search_intermediate_tree(node, 0); \
    return 1; \
} \
 \
static int __mse_generate_set_##fname##_lt_inc(mse_set_generator_t *gen, \
        mse_search_intermediate_t *res, \
        mse_all_printings_cards_t *cards, \
        float arg) \
{ \
    /* Prepare the bounds of the search */ \
    mse_card_t lower; \
    memset(&lower, 0xFF, sizeof(lower)); \
    lower.id = mse_max_uuid(); \
 \
    lower.fname = arg; \
 \
    /* Search the tree */ \
    mse_avl_tree_node_t *node = NULL; \
    ASSERT(mse_tree_lookup(cards->indexes.card_##fname##_tree, &node, 1, (void *) &lower)); \
    *res = mse_init_search_intermediate_tree(node, 0); \
    return 1; \
} \
 \
static int __mse_generate_set_##fname##_gt(mse_set_generator_t *gen, \
                                       mse_search_intermediate_t *res, \
                                       mse_all_printings_cards_t *cards, \
                                       float arg) \
{ \
    /* Prepare the bounds of the search */ \
    mse_card_t lower; \
    memset(&lower, 0xFF, sizeof(lower)); \
    lower.id = mse_max_uuid(); \
    lower.fname = arg; \
 \
    /* Search the tree */ \
    mse_avl_tree_node_t *node = NULL; \
    ASSERT(mse_tree_lookup(cards->indexes.card_##fname##_tree, &node, 0, (void *) &lower)); \
    *res = mse_init_search_intermediate_tree(node, 0); \
    return 1; \
} \
 \
static int __mse_generate_set_##fname##_gt_inc(mse_set_generator_t *gen, \
        mse_search_intermediate_t *res, \
        mse_all_printings_cards_t *cards, \
        float arg) \
{ \
    /* Prepare the bounds of the search */ \
    mse_card_t lower; \
    memset(&lower, 0, sizeof(lower)); \
    lower.id = mse_min_uuid(); \
    lower.fname = arg; \
 \
    /* Search the tree */ \
    mse_avl_tree_node_t *node = NULL; \
    ASSERT(mse_tree_lookup(cards->indexes.card_##fname##_tree, &node, 0, (void *) &lower)); \
    *res = mse_init_search_intermediate_tree(node, 0); \
    return 1; \
} \
 \
int mse_generate_set_##fname(mse_set_generator_t *gen, \
                           mse_search_intermediate_t *res, \
                           mse_all_printings_cards_t *cards) \
{ \
    float arg; \
    ASSERT(mse_to_float(gen->argument, &arg)); \
 \
    if (gen->negate) { \
        switch(gen->generator_op) { \
        case MSE_SET_GENERATOR_OP_INCLUDES: \
        case MSE_SET_GENERATOR_OP_EQUALS: \
            return __mse_generate_set_##fname##_ne(gen, res, cards, arg); \
        case MSE_SET_GENERATOR_OP_LT: \
            return __mse_generate_set_##fname##_gt_inc(gen, res, cards, arg); \
        case MSE_SET_GENERATOR_OP_LT_INC: \
            return __mse_generate_set_##fname##_gt(gen, res, cards, arg); \
        case MSE_SET_GENERATOR_OP_GT: \
            return __mse_generate_set_##fname##_lt_inc(gen, res, cards, arg); \
        case MSE_SET_GENERATOR_OP_GT_INC: \
            return __mse_generate_set_##fname##_lt(gen, res, cards, arg); \
        } \
    } else { \
        switch(gen->generator_op) { \
        case MSE_SET_GENERATOR_OP_INCLUDES: \
        case MSE_SET_GENERATOR_OP_EQUALS: \
            return __mse_generate_set_##fname##_eq(gen, res, cards, arg); \
        case MSE_SET_GENERATOR_OP_LT: \
            return __mse_generate_set_##fname##_lt(gen, res, cards, arg); \
        case MSE_SET_GENERATOR_OP_LT_INC: \
            return __mse_generate_set_##fname##_lt_inc(gen, res, cards, arg); \
        case MSE_SET_GENERATOR_OP_GT: \
            return __mse_generate_set_##fname##_gt(gen, res, cards, arg); \
        case MSE_SET_GENERATOR_OP_GT_INC: \
            return __mse_generate_set_##fname##_gt_inc(gen, res, cards, arg); \
        } \
    } \
 \
    lprintf(LOG_ERROR, "Cannot find operation %d for " #fname "\n", gen->generator_op); \
    return 0; \
}

MSE_GENERATOR_FIELD_GENERATOR(power)

MSE_GENERATOR_FIELD_GENERATOR(toughness)

MSE_GENERATOR_FIELD_GENERATOR(cmc)

MSE_GENERATOR_FIELD_GENERATOR(loyalty)
