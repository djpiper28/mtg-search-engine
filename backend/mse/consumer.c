#include "./consumer.h"
#include "./card_str_match.h"
#include "../testing_h/testing.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Oracle consumers
static int __mse_consume_set_oracle_re(mse_set_consumer_t *gen,
                                       mse_search_intermediate_t *res,
                                       mse_search_intermediate_t *cards)
{
    char *re = mse_escape_regex(gen->argument);
    ASSERT(re != NULL);

    mse_avl_tree_node_t *node = NULL;
    int status = mse_matching_card_oracle(&node, cards->node, re, 1, 0);
    *res = mse_init_search_intermediate_tree(node, 0);
    free(re);

    ASSERT(status);
    return 1;
}

static int __mse_consume_set_oracle_text_inc(mse_set_consumer_t *gen,
        mse_search_intermediate_t *res,
        mse_search_intermediate_t *cards)
{
    mse_avl_tree_node_t *node = NULL;
    ASSERT(mse_matching_card_oracle(&node, cards->node, gen->argument, 0, 0));
    *res = mse_init_search_intermediate_tree(node, 0);
    return 1;
}

static int mse_consume_set_oracle(mse_set_consumer_t *gen,
                                  mse_search_intermediate_t *res,
                                  mse_search_intermediate_t *cards)
{
    if (mse_is_regex_str(gen->argument)) {
        return __mse_consume_set_oracle_re(gen, res, cards);
    } else {
        return __mse_consume_set_oracle_text_inc(gen, res, cards);
    }
}

// Name consumers
static int __mse_consume_set_name_re(mse_set_consumer_t *gen,
                                     mse_search_intermediate_t *res,
                                     mse_search_intermediate_t *cards)
{
    char *re = mse_escape_regex(gen->argument);
    ASSERT(re != NULL);

    mse_avl_tree_node_t *node = NULL;
    int status = mse_matching_card_name(&node, cards->node, re, 1, 0);
    *res = mse_init_search_intermediate_tree(node, 0);
    free(re);

    ASSERT(status);
    return 1;
}

static int __mse_consume_set_name_text_inc(mse_set_consumer_t *gen,
        mse_search_intermediate_t *res,
        mse_search_intermediate_t *cards)
{
    mse_avl_tree_node_t *node = NULL;
    ASSERT(mse_matching_card_name(&node, cards->node, gen->argument, 0, 0));
    *res = mse_init_search_intermediate_tree(node, 0);
    return 1;
}

static int mse_consume_set_name(mse_set_consumer_t *gen,
                                mse_search_intermediate_t *res,
                                mse_search_intermediate_t *cards)
{
    if (mse_is_regex_str(gen->argument)) {
        return __mse_consume_set_name_re(gen, res, cards);
    } else {
        return __mse_consume_set_name_text_inc(gen, res, cards);
    }
}

int mse_init_set_consumer(mse_set_consumer_t *ret,
                          mse_set_consumer_type_t gen_type,
                          char *argument,
                          size_t len)
{
    memset(ret, 0, sizeof(*ret));
    ret->generator_type = gen_type;

    size_t buf_len = sizeof(*ret->argument) * (len + 1);
    ASSERT(ret->argument = malloc(buf_len));

    // strlcpy is not defined :(
    memset(ret->argument, 0, buf_len);
    memcpy(ret->argument, argument, len);
    return 1;
}

void mse_free_set_consumer(mse_set_consumer_t *gen)
{
    if (gen->argument != NULL) {
        free(gen->argument);
    }
    memset(gen, 0, sizeof(*gen));
}

int mse_consume_set(mse_set_consumer_t *gen,
                    mse_search_intermediate_t *res,
                    mse_all_printings_cards_t *cards,
                    mse_search_intermediate_t *child)
{
    memset(res, 0, sizeof(*res));
    switch(gen->generator_type) {
    case MSE_SET_CONSUMER_ORACLE:
        return mse_consume_set_oracle(gen, res, child);
    case MSE_SET_CONSUMER_NAME:
        return mse_consume_set_name(gen, res, child);
    case MSE_SET_CONSUMER_NEGATE:
        return mse_set_negate(res, cards, child);
    }
    return 1;
}
