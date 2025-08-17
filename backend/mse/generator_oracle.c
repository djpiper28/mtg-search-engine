#include "./generator_oracle.h"
#include "./card_str_match.h"
#include "../testing_h/testing.h"
#include <string.h>

static int __mse_generate_set_oracle_re(mse_set_generator_t *gen,
                                        mse_search_intermediate_t *res,
                                        mse_all_printings_cards_t *cards)
{
    char *re = mse_escape_regex(gen->argument);
    ASSERT(re != NULL);

    mse_avl_tree_node_t *node = NULL;
    int status = mse_matching_card_oracle(&node, cards->card_tree, re, 1, gen->negate);
    *res = mse_init_search_intermediate_tree(node, 0);
    free(re);

    ASSERT(status);
    return 1;
}

static int __mse_generate_set_oracle_text_inc(mse_set_generator_t *gen,
        mse_search_intermediate_t *res,
        mse_all_printings_cards_t *cards)
{
    mse_avl_tree_node_t *node = NULL;
    ASSERT(mse_matching_card_oracle(&node, cards->card_tree, gen->argument, 0, gen->negate));
    *res = mse_init_search_intermediate_tree(node, 0);
    return 1;
}

int mse_generate_set_oracle(mse_set_generator_t *gen,
                            mse_search_intermediate_t *res,
                            mse_all_printings_cards_t *cards)
{
    if (mse_is_regex_str(gen->argument)) {
        return __mse_generate_set_oracle_re(gen, res, cards);
    } else {
        return __mse_generate_set_oracle_text_inc(gen, res, cards);
    }
}
