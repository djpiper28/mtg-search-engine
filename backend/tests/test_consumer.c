#include "../testing_h/testing.h"
#include "../mse/consumer.h"
#include "../mse/generators.h"
#include "./test_generators.h"
#include <string.h>

#define ARGUMENT "wee"
#define ARGUMENT_RE "/.*hopt.*/"

static int test_consumer_init_free()
{
    mse_set_consumer_t consumer;
    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_NEGATE,
                                 "",
                                 0));
    ASSERT(consumer.generator_type == MSE_SET_CONSUMER_NEGATE);
    ASSERT(consumer.argument != NULL);
    ASSERT(strlen(consumer.argument) == 0);
    mse_free_set_consumer(&consumer);

    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_ORACLE,
                                 ARGUMENT,
                                 strlen(ARGUMENT)));
    ASSERT(consumer.generator_type == MSE_SET_CONSUMER_ORACLE);
    ASSERT(consumer.argument != NULL);
    ASSERT(strcmp(consumer.argument, ARGUMENT) == 0);
    mse_free_set_consumer(&consumer);

    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_NAME,
                                 ARGUMENT,
                                 strlen(ARGUMENT)));
    ASSERT(consumer.generator_type == MSE_SET_CONSUMER_NAME);
    ASSERT(consumer.argument != NULL);
    ASSERT(strcmp(consumer.argument, ARGUMENT) == 0);
    mse_free_set_consumer(&consumer);
    return 1;
}

static int test_consumer_negate_no_cards()
{
    mse_set_consumer_t consumer;
    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_NEGATE,
                                 "",
                                 0));

    mse_avl_tree_node_t *root = NULL;
    mse_search_intermediate_t ret, child;
    memset(&child, 0, sizeof(child));
    child.node = root;

    ASSERT(mse_consume_set(&consumer, &ret, &gen_cards, &child));
    ASSERT(mse_tree_size(ret.node) == mse_tree_size(gen_cards.card_tree));

    mse_free_search_intermediate(&ret);
    mse_free_set_consumer(&consumer);
    return 1;
}

static int test_consumer_negate_normal_case()
{
    mse_set_consumer_t consumer;
    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_NEGATE,
                                 "",
                                 0));

    mse_search_intermediate_t ret, child;
    mse_set_generator_t generator;
    ASSERT(mse_init_set_generator(&generator,
                                  MSE_SET_GENERATOR_ORACLE_TEXT,
                                  MSE_SET_GENERATOR_OP_EQUALS,
                                  ARGUMENT_RE,
                                  strlen(ARGUMENT_RE)));
    ASSERT(mse_generate_set(&generator, &child, &gen_cards));
    mse_free_set_generator(&generator);

    ASSERT(mse_consume_set(&consumer, &ret, &gen_cards, &child));
    ASSERT(mse_tree_size(ret.node) == mse_tree_size(gen_cards.card_tree) - mse_tree_size(child.node));

    mse_free_search_intermediate(&ret);
    mse_free_search_intermediate(&child);
    mse_free_set_consumer(&consumer);
    return 1;
}

static int test_consumer_oracle_re()
{
    mse_set_consumer_t consumer;
    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_ORACLE,
                                 ARGUMENT_RE,
                                 strlen(ARGUMENT_RE)));

    mse_search_intermediate_t ret, child;
    memset(&child, 0, sizeof(child));
    child.node = gen_cards.card_tree; // Freeing child will now cause a shit ton of errors, so don't do that.

    ASSERT(mse_consume_set(&consumer, &ret, &gen_cards, &child));
    ASSERT(mse_tree_size(ret.node) > 0);

    mse_free_search_intermediate(&ret);
    mse_free_set_consumer(&consumer);
    return 1;
}

static int test_consumer_name_re()
{
    mse_set_consumer_t consumer;
    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_NAME,
                                 ARGUMENT_RE,
                                 strlen(ARGUMENT_RE)));

    mse_search_intermediate_t ret, child;
    memset(&child, 0, sizeof(child));
    child.node = gen_cards.card_tree; // Freeing child will now cause a shit ton of errors, so don't do that.

    ASSERT(mse_consume_set(&consumer, &ret, &gen_cards, &child));
    ASSERT(mse_tree_size(ret.node) > 0);

    mse_free_search_intermediate(&ret);
    mse_free_set_consumer(&consumer);
    return 1;
}

static int test_consumer_oracle_txt()
{
    mse_set_consumer_t consumer;
    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_ORACLE,
                                 ARGUMENT,
                                 strlen(ARGUMENT)));

    mse_search_intermediate_t ret, child;
    memset(&child, 0, sizeof(child));
    child.node = gen_cards.card_tree; // Freeing child will now cause a shit ton of errors, so don't do that.

    ASSERT(mse_consume_set(&consumer, &ret, &gen_cards, &child));
    ASSERT(mse_tree_size(ret.node) > 0);

    mse_free_search_intermediate(&ret);
    mse_free_set_consumer(&consumer);
    return 1;
}

static int test_consumer_name_txt()
{
    mse_set_consumer_t consumer;
    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_NAME,
                                 ARGUMENT,
                                 strlen(ARGUMENT)));

    mse_search_intermediate_t ret, child;
    memset(&child, 0, sizeof(child));
    child.node = gen_cards.card_tree; // Freeing child will now cause a shit ton of errors, so don't do that.

    ASSERT(mse_consume_set(&consumer, &ret, &gen_cards, &child));
    ASSERT(mse_tree_size(ret.node) > 0);

    mse_free_search_intermediate(&ret);
    mse_free_set_consumer(&consumer);
    return 1;
}

SUB_TEST(test_consumer, {&test_consumer_init_free, "Test consumer init and free"},
{&test_consumer_negate_no_cards, "Test consumer negate NULL tree"},
{&test_consumer_negate_normal_case, "Test consumer negate"},
{&test_consumer_oracle_re, "Test consumer oracle re"},
{&test_consumer_name_re, "Test consumer name re"},
{&test_consumer_oracle_txt, "Test consumer oracle txt"},
{&test_consumer_name_txt, "Test consumer name txt"})
