#include "./test_generators.h"
#include "../mse/generators.h"
#include "../testing_h/testing.h"
#include <string.h>

#define TYPE_ARG "god legendary"
#define TYPE_TRIE_MIN 60

static int test_generator_type_trie()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_TYPE;
    size_t len = strlen(TYPE_ARG);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_EQUALS, TYPE_ARG, len));

    mse_search_intermediate_t inter;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > TYPE_TRIE_MIN);
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, TYPE_ARG, len));
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > TYPE_TRIE_MIN);
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    return 1;
}

static int test_generator_type_trie_negate()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_TYPE;
    size_t len = strlen(TYPE_ARG);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_EQUALS, TYPE_ARG, len));

    mse_search_intermediate_t inter;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > TYPE_TRIE_MIN);
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // No negate
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, TYPE_ARG, len));
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    size_t size_1;
    ASSERT(size_1 = mse_tree_size(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // With negate
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, TYPE_ARG, len));
    ret.negate = 1;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    size_t size_2;
    ASSERT(size_2 = mse_tree_size(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    ASSERT(size_1 != size_2);
    return 1;
}

SUB_TEST(test_generator_type, {&test_generator_type_trie, "Test generator type trie"},
{&test_generator_type_trie_negate, "Test generator type trie negate"})
