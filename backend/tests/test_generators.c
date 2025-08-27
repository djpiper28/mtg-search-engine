#include "./test_generators.h"
#include "../testing_h/testing.h"
#include "../mse/generators.h"
#include "../mse/save.h"
#include <string.h>

#define DEFAULT_ARGUMENT "thopt"

mse_thread_pool_t gen_thread_pool;
mse_all_printings_cards_t gen_cards;

static int init_generator_tests()
{
    ASSERT(mse_init_pool(&gen_thread_pool));
    ASSERT(mse_get_cards_from_file(&gen_cards, &gen_thread_pool));
    ASSERT(gen_cards.card_tree != NULL);
    return 1;
}

static int free_generator_tests()
{
    mse_free_all_printings_cards(&gen_cards);
    ASSERT(mse_free_pool(&gen_thread_pool));
    return 1;
}

static int test_generator_init_free()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_COLOUR;
    mse_set_generator_operator_t op_type = MSE_SET_GENERATOR_OP_LT_INC;
    size_t len = strlen(DEFAULT_ARGUMENT);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, op_type, DEFAULT_ARGUMENT, len));

    ASSERT(ret.argument != NULL);
    ASSERT(strcmp(ret.argument, DEFAULT_ARGUMENT) == 0);
    ASSERT(ret.generator_type == gen_type);
    ASSERT(ret.generator_op == op_type);

    mse_free_set_generator(&ret);

    // Test NULL generator
    memset(&ret, 0, sizeof(ret));
    mse_free_set_generator(&ret);
    return 1;
}

SUB_TEST(test_generators, {&init_generator_tests, "Init generator tests"},
{&test_generator_init_free, "Test generator init free"},
{&test_generator_validation, "Test generator validation"},
{&test_set_generators_float_fields, "Test set generators float fields"},
{&test_generator_set, "Test set generators"},
{&test_generator_txt, "Test txt generators (name & oracle)"},
{&test_generator_colours, "Test colours generators"},
{&test_generator_type, "Test type generator"},
{&test_consumer, "Test consumers"},
{&free_generator_tests, "Free generator tests"})
