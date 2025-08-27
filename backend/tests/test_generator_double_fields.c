#include "./test_generators.h"
#include "../testing_h/testing.h"
#include "../mse/avl_tree.h"
#include "../mse/generators.h"
#include <string.h>
#include <math.h>

#define BAD_ARGUMENT "12341234123412341234sjaskldjaslkdjasld :()"
#define DEFAULT_ARGUMENT "5"
#define DEFAULT_ARGUMENT_DOUBLE atof(DEFAULT_ARGUMENT)

static int found_eq;

#define TEST_FEILD_GENERATORS_FUNC_FOR(fname, type_name_suffix) \
static int __test_generator_##fname(mse_set_generator_operator_t op_type, int (*test_tree)(mse_avl_tree_node_t *node)) \
{ \
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_##type_name_suffix; \
    size_t len = strlen(DEFAULT_ARGUMENT); \
 \
    mse_set_generator_t ret; \
    ASSERT(mse_init_set_generator(&ret, gen_type, op_type, DEFAULT_ARGUMENT, len)); \
 \
    mse_search_intermediate_t inter; \
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards)); \
    ASSERT(mse_tree_size(inter.node) > 0); \
    ASSERT(test_tree(inter.node)); \
    mse_free_search_intermediate(&inter); \
    mse_free_set_generator(&ret); \
    return 1; \
} \
 \
static int test_generator_##fname##_invalid_arg() \
{ \
    mse_set_generator_operator_t op_type = MSE_SET_GENERATOR_OP_LT; \
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_##type_name_suffix; \
    size_t len = strlen(BAD_ARGUMENT); \
 \
    mse_set_generator_t ret; \
    ASSERT(mse_init_set_generator(&ret, gen_type, op_type, BAD_ARGUMENT, len)); \
 \
    mse_search_intermediate_t inter; \
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards) == 0); \
    mse_free_set_generator(&ret); \
    return 1; \
} \
 \
static int test_tree_##fname##_eq(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT((int) DEFAULT_ARGUMENT_DOUBLE == (int) fname); \
    ASSERT(test_tree_##fname##_eq(node->l)); \
    ASSERT(test_tree_##fname##_eq(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_eq() \
{ \
    ASSERT(__test_generator_##fname(MSE_SET_GENERATOR_OP_EQUALS, test_tree_##fname##_eq)); \
    return 1; \
} \
 \
static int test_generator_##fname##_inc() \
{ \
    ASSERT(__test_generator_##fname(MSE_SET_GENERATOR_OP_INCLUDES, test_tree_##fname##_eq)); \
    return 1; \
} \
 \
static int test_tree_##fname##_lt(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT(fname < DEFAULT_ARGUMENT_DOUBLE); \
    ASSERT(fabs(DEFAULT_ARGUMENT_DOUBLE - fname) > 0.01); \
    ASSERT(test_tree_##fname##_lt(node->l)); \
    ASSERT(test_tree_##fname##_lt(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_lt() \
{ \
    ASSERT(__test_generator_##fname(MSE_SET_GENERATOR_OP_LT, test_tree_##fname##_lt)); \
    return 1; \
} \
 \
static int test_tree_##fname##_lt_inc(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT(fname <= DEFAULT_ARGUMENT_DOUBLE ); \
    found_eq |= (int) DEFAULT_ARGUMENT_DOUBLE == (int) fname; \
    ASSERT(test_tree_##fname##_lt_inc(node->l)); \
    ASSERT(test_tree_##fname##_lt_inc(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_lt_inc() \
{ \
    found_eq = 0; \
    ASSERT(__test_generator_##fname(MSE_SET_GENERATOR_OP_LT_INC, &test_tree_##fname##_lt_inc)); \
    ASSERT(found_eq); \
    return 1; \
} \
 \
static int test_tree_##fname##_gt(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT(fname > DEFAULT_ARGUMENT_DOUBLE); \
    ASSERT(fabs(DEFAULT_ARGUMENT_DOUBLE - fname) > 0.01); \
    ASSERT(test_tree_##fname##_gt(node->l)); \
    ASSERT(test_tree_##fname##_gt(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_gt() \
{ \
    ASSERT(__test_generator_##fname(MSE_SET_GENERATOR_OP_GT, &test_tree_##fname##_gt)); \
    return 1; \
} \
 \
static int test_tree_##fname##_gt_inc(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT(fname >= DEFAULT_ARGUMENT_DOUBLE); \
    found_eq |= (int) DEFAULT_ARGUMENT_DOUBLE == (int) fname; \
    ASSERT(test_tree_##fname##_gt_inc(node->l)); \
    ASSERT(test_tree_##fname##_gt_inc(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_gt_inc() \
{ \
    found_eq = 0; \
    ASSERT(__test_generator_##fname(MSE_SET_GENERATOR_OP_GT_INC, &test_tree_##fname##_gt_inc)); \
    ASSERT(found_eq); \
    return 1; \
} \
/* Negate tests */ \
static int __test_generator_##fname##_n(mse_set_generator_operator_t op_type, int (*test_tree)(mse_avl_tree_node_t *node)) \
{ \
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_##type_name_suffix; \
    size_t len = strlen(DEFAULT_ARGUMENT); \
 \
    mse_set_generator_t ret; \
    ASSERT(mse_init_set_generator(&ret, gen_type, op_type, DEFAULT_ARGUMENT, len)); \
    ret.negate = 1; \
 \
    mse_search_intermediate_t inter; \
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards)); \
    ASSERT(mse_tree_size(inter.node) > 0); \
    ASSERT(test_tree(inter.node)); \
    mse_free_search_intermediate(&inter); \
    mse_free_set_generator(&ret); \
    return 1; \
} \
 \
static int test_tree_##fname##_eq_n(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT((int) DEFAULT_ARGUMENT_DOUBLE != (int) fname); \
    ASSERT(test_tree_##fname##_eq_n(node->l)); \
    ASSERT(test_tree_##fname##_eq_n(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_eq_n() \
{ \
    ASSERT(__test_generator_##fname##_n(MSE_SET_GENERATOR_OP_EQUALS, test_tree_##fname##_eq_n)); \
    return 1; \
} \
 \
static int test_generator_##fname##_inc_n() \
{ \
    ASSERT(__test_generator_##fname##_n(MSE_SET_GENERATOR_OP_INCLUDES, test_tree_##fname##_eq_n)); \
    return 1; \
} \
 \
static int test_tree_##fname##_lt_n(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT(!(fname < DEFAULT_ARGUMENT_DOUBLE)); \
    ASSERT(test_tree_##fname##_lt_n(node->l)); \
    ASSERT(test_tree_##fname##_lt_n(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_lt_n() \
{ \
    ASSERT(__test_generator_##fname##_n(MSE_SET_GENERATOR_OP_LT, test_tree_##fname##_lt_n)); \
    return 1; \
} \
 \
static int test_tree_##fname##_lt_inc_n(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT(!(fname <= DEFAULT_ARGUMENT_DOUBLE)); \
    found_eq |= (int) DEFAULT_ARGUMENT_DOUBLE == (int) fname; \
    ASSERT(test_tree_##fname##_lt_inc_n(node->l)); \
    ASSERT(test_tree_##fname##_lt_inc_n(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_lt_inc_n() \
{ \
    found_eq = 0; \
    ASSERT(__test_generator_##fname##_n(MSE_SET_GENERATOR_OP_LT_INC, &test_tree_##fname##_lt_inc_n)); \
    ASSERT(!found_eq); \
    return 1; \
} \
 \
static int test_tree_##fname##_gt_n(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT(!(fname > DEFAULT_ARGUMENT_DOUBLE)); \
    ASSERT(test_tree_##fname##_gt_n(node->l)); \
    ASSERT(test_tree_##fname##_gt_n(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_gt_n() \
{ \
    ASSERT(__test_generator_##fname##_n(MSE_SET_GENERATOR_OP_GT, &test_tree_##fname##_gt_n)); \
    return 1; \
} \
 \
static int test_tree_##fname##_gt_inc_n(mse_avl_tree_node_t *node) \
{ \
    if (node == NULL) { \
        return 1; \
    } \
 \
    float fname = ((mse_card_t *) node->payload)->fname; \
    ASSERT(!(fname >= DEFAULT_ARGUMENT_DOUBLE)); \
    found_eq |= (int) DEFAULT_ARGUMENT_DOUBLE == (int) fname; \
    ASSERT(test_tree_##fname##_gt_inc_n(node->l)); \
    ASSERT(test_tree_##fname##_gt_inc_n(node->r)); \
    return 1; \
} \
 \
static int test_generator_##fname##_gt_inc_n() \
{ \
    found_eq = 0; \
    ASSERT(__test_generator_##fname##_n(MSE_SET_GENERATOR_OP_GT_INC, &test_tree_##fname##_gt_inc_n)); \
    ASSERT(!found_eq); \
    return 1; \
}

#define TEST_FEILD_GENERATORS_FOR(fname) \
{&test_generator_##fname##_invalid_arg, "Test generator " #fname " invalid arg"}, \
{&test_generator_##fname##_eq, "Test generator " #fname " ="}, \
{&test_generator_##fname##_inc, "Test generator " #fname " :"}, \
{&test_generator_##fname##_lt, "Test genreator " #fname " <"}, \
{&test_generator_##fname##_lt_inc, "Test genreator " #fname " <="}, \
{&test_generator_##fname##_gt, "Test genreator " #fname " >"}, \
{&test_generator_##fname##_gt_inc, "Test genreator " #fname " >="}, \
{&test_generator_##fname##_eq_n, "Test generator " #fname " = negate"}, \
{&test_generator_##fname##_inc_n, "Test generator " #fname " : negate"}, \
{&test_generator_##fname##_lt_n, "Test genreator " #fname " < negate"}, \
{&test_generator_##fname##_lt_inc_n, "Test genreator " #fname " <= negate"}, \
{&test_generator_##fname##_gt_n, "Test genreator " #fname " > negate"}, \
{&test_generator_##fname##_gt_inc_n, "Test genreator " #fname " >= negate"}

TEST_FEILD_GENERATORS_FUNC_FOR(power, POWER)
TEST_FEILD_GENERATORS_FUNC_FOR(toughness, TOUGHNESS)
TEST_FEILD_GENERATORS_FUNC_FOR(cmc, CMC)
TEST_FEILD_GENERATORS_FUNC_FOR(loyalty, LOYALTY)

SUB_TEST(test_set_generators_float_fields, TEST_FEILD_GENERATORS_FOR(power),
         TEST_FEILD_GENERATORS_FOR(toughness),
         TEST_FEILD_GENERATORS_FOR(cmc),
         TEST_FEILD_GENERATORS_FOR(loyalty))
