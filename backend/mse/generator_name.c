#include "./generator_name.h"
#include "./card_str_match.h"
#include "./card_txt_fields_trie.h"
#include "./search.h"
#include "../testing_h/testing.h"
#include <string.h>

static int __mse_generate_set_name_re(mse_set_generator_t *gen,
                                      mse_search_intermediate_t *res,
                                      mse_all_printings_cards_t *cards)
{
    char *re = mse_escape_regex(gen->argument);
    ASSERT(re != NULL);

    mse_avl_tree_node_t *node = NULL;
    int status = mse_matching_card_name(&node, cards->card_tree, re, 1, gen->negate);
    *res = mse_init_search_intermediate_tree(node, 0);
    free(re);

    ASSERT(status);
    return 1;
}

static int __mse_generate_set_name_text_inc(mse_set_generator_t *gen,
        mse_search_intermediate_t *res,
        mse_all_printings_cards_t *cards)
{
    // Split the name into pieces
    mse_card_name_parts_t parts;
    ASSERT(mse_split_card_name(gen->argument, &parts));

    // Calculate the sets for each part
    mse_search_intermediate_t search_tmp;
    memset(&search_tmp, 0, sizeof(search_tmp));

    // Calculate the set intersection of all of the parts
    int code = 1;
    for (size_t i = 0; i < parts.len; i++) {
        mse_search_intermediate_t tmp, tmp_trie;
        memset(&tmp, 0, sizeof(tmp));
        tmp_trie = tmp;

        int r = mse_card_trie_lookup_aprox(cards->indexes.card_name_parts_trie, parts.parts[i], &tmp_trie.node);
        if (!r) {
            lprintf(LOG_ERROR, "Cannot lookup the trie\n");
            code = 0;
            break;
        }

        r = mse_set_union(&tmp, &search_tmp, &tmp_trie);

        // Free before the error check
        mse_free_search_intermediate(&tmp_trie);
        if (!r) {
            lprintf(LOG_ERROR, "Cannot generate set union\n");
            code = 0;
            break;
        }

        mse_free_search_intermediate(&search_tmp);
        search_tmp = tmp;
    }

    if (gen->negate) {
        mse_search_intermediate_t tmp;
        memset(&tmp, 0, sizeof(tmp));

        int r = mse_set_negate(&tmp, cards, &search_tmp);
        if (!r) {
            lprintf(LOG_ERROR, "Cannot negate set\n");
            code = 0;
        }

        mse_free_search_intermediate(&search_tmp);
        search_tmp = tmp;
    }

    // Cleanup
    mse_free_card_parts(&parts);
    if (!code) {
        mse_free_search_intermediate(&search_tmp);
        lprintf(LOG_ERROR, "Cannot generate set for name text inc\n");
        return 0;
    }

    *res = mse_init_search_intermediate_tree(search_tmp.node, 0);
    return 1;
}

int mse_generate_set_name(mse_set_generator_t *gen,
                          mse_search_intermediate_t *res,
                          mse_all_printings_cards_t *cards)
{
    if (mse_is_regex_str(gen->argument)) {
        return __mse_generate_set_name_re(gen, res, cards);
    } else {
        return __mse_generate_set_name_text_inc(gen, res, cards);
    }
}
