#include "./test_generators.h"
#include "../testing_h/testing.h"
#include "../mse/card.h"
#include "../mse/avl_tree.h"
#include "../mse/generators.h"
#include <string.h>

#define DEFAULT_ARGUMENT "m20"

static int test_tree(mse_avl_tree_node_t *node)
{
    if (node == NULL) {
        return 1;
    }

    mse_card_t *card = (mse_card_t *) node->payload;
    int found = 0;
    for (size_t i = 0; i < card->set_codes_count; i++) {
        found |= memcmp(card->set_codes[i], DEFAULT_ARGUMENT, 3) == 0;
        if (found) {
            break;
        }
    }
    ASSERT(found);

    ASSERT(test_tree(node->l));
    ASSERT(test_tree(node->r));
    return 1;
}

static int test_tree_negate(mse_avl_tree_node_t *node)
{
    if (node == NULL) {
        return 1;
    }

    mse_card_t *card = (mse_card_t *) node->payload;
    int found = 0;
    for (size_t i = 0; i < card->set_codes_count; i++) {
        found |= memcmp(card->set_codes[i], DEFAULT_ARGUMENT, 3) == 0;
        if (found) {
            break;
        }
    }
    ASSERT(!found);

    ASSERT(test_tree_negate(node->l));
    ASSERT(test_tree_negate(node->r));
    return 1;
}

int test_generator_set()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_SET;
    size_t len = strlen(DEFAULT_ARGUMENT);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_EQUALS, DEFAULT_ARGUMENT, len));

    mse_search_intermediate_t inter;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > 0);
    ASSERT(test_tree(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // Test includes
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, DEFAULT_ARGUMENT, len));
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > 0);
    ASSERT(test_tree(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // Test negate
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, DEFAULT_ARGUMENT, len));
    ret.negate = 1;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > 0);
    ASSERT(test_tree_negate(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);
    return 1;
}
