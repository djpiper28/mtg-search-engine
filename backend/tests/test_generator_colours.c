#include "./test_generators.h"
#include "../mse/card.h"
#include "../mse/generators.h"
#include "../mse/avl_tree.h"
#include "../testing_h/testing.h"
#include <string.h>

#define DEFAULT_ARGUMENT (MSE_WHITE | MSE_BLUE)
#define DEFAULT_ARGUMENT_STR "WU"

#define COLOUR_GEN_TEST(op_l, op_u, op) \
static int test_tree_c_##op_l(mse_avl_tree_node_t *node, int negate) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    mse_card_t *card = (mse_card_t *) node->payload; \
    ASSERT(mse_colour_##op(card->colours, DEFAULT_ARGUMENT) != negate); \
 \
    ASSERT(test_tree_c_##op_l(node->l, negate)); \
    ASSERT(test_tree_c_##op_l(node->r, negate)); \
    return 1; \
} \
 \
static int test_generator_colours_##op_l() \
{ \
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_COLOUR; \
    size_t len = strlen(DEFAULT_ARGUMENT_STR); \
 \
    mse_set_generator_t ret; \
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_##op_u, DEFAULT_ARGUMENT_STR, len)); \
 \
    mse_search_intermediate_t inter; \
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards)); \
    ASSERT(mse_tree_size(inter.node) > 0); \
    ASSERT(test_tree_c_##op_l(inter.node, ret.negate)); \
 \
    ret.negate = 1; \
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards)); \
    ASSERT(mse_tree_size(inter.node) > 0); \
    ASSERT(test_tree_c_##op_l(inter.node, ret.negate)); \
 \
    mse_free_search_intermediate(&inter); \
    mse_free_set_generator(&ret); \
    return 1; \
}

COLOUR_GEN_TEST(lt, LT, lt)
COLOUR_GEN_TEST(lt_inc, LT_INC, lt_inc)
COLOUR_GEN_TEST(gt, GT, gt)
COLOUR_GEN_TEST(gt_inc, GT_INC, gt_inc)
COLOUR_GEN_TEST(eq, EQUALS, eq)
COLOUR_GEN_TEST(inc, INCLUDES, gt_inc)

#define COLOUR_IDENTITY_GEN_TEST(op_l, op_u, op) \
static int test_tree_ci_##op_l(mse_avl_tree_node_t *node, int negate) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    mse_card_t *card = (mse_card_t *) node->payload; \
    ASSERT(mse_colour_##op(card->colour_identity, DEFAULT_ARGUMENT) != negate); \
 \
    ASSERT(test_tree_ci_##op_l(node->l, negate)); \
    ASSERT(test_tree_ci_##op_l(node->r, negate)); \
    return 1; \
} \
 \
static int test_generator_colour_identity_##op_l() \
{ \
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_COLOUR_IDENTITY; \
    size_t len = strlen(DEFAULT_ARGUMENT_STR); \
 \
    mse_set_generator_t ret; \
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_##op_u, DEFAULT_ARGUMENT_STR, len)); \
 \
    mse_search_intermediate_t inter; \
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards)); \
    ASSERT(mse_tree_size(inter.node) > 0); \
    ASSERT(test_tree_ci_##op_l(inter.node, ret.negate)); \
 \
    ret.negate = 1; \
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards)); \
    ASSERT(mse_tree_size(inter.node) > 0); \
    ASSERT(test_tree_ci_##op_l(inter.node, ret.negate)); \
    mse_free_search_intermediate(&inter); \
    mse_free_set_generator(&ret); \
    return 1; \
}

COLOUR_IDENTITY_GEN_TEST(lt, LT, lt)
COLOUR_IDENTITY_GEN_TEST(lt_inc, LT_INC, lt_inc)
COLOUR_IDENTITY_GEN_TEST(gt, GT, gt)
COLOUR_IDENTITY_GEN_TEST(gt_inc, GT_INC, gt_inc)
COLOUR_IDENTITY_GEN_TEST(eq, EQUALS, eq)
COLOUR_IDENTITY_GEN_TEST(inc, INCLUDES, gt_inc)

SUB_TEST(test_generator_colours, {&test_generator_colours_lt, "Colours generator <="},
{&test_generator_colours_lt_inc, "Colours generator <="},
{&test_generator_colours_gt, "Colours generator >"},
{&test_generator_colours_gt_inc, "Colours generator >="},
{&test_generator_colours_eq, "Colours generator =="},
{&test_generator_colours_inc, "Colours generator : (inc)"},
{&test_generator_colour_identity_lt, "Colour identity generator <="},
{&test_generator_colour_identity_lt_inc, "Colour identity generator <="},
{&test_generator_colour_identity_gt, "Colour identity generator >"},
{&test_generator_colour_identity_gt_inc, "Colour identity generator >="},
{&test_generator_colour_identity_eq, "Colour identity generator =="},
{&test_generator_colour_identity_inc, "Colour identity generator : (inc)"})
