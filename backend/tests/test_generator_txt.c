#include "./test_generators.h"
#include "../mse/generators.h"
#include "../mse/card_str_match.h"
#include "../testing_h/testing.h"
#include <string.h>
#include <regex.h>

#define REGEX_ARG "/.*god of (the )?.*/"
#define REGEX2_ARG "/.*drAw.*/"
#define ARG "hAstE"
#define ARG_LOWER "haste"

static int test_tree_oracle_re(mse_avl_tree_node_t *node)
{
    if (node == NULL) {
        return 1;
    }

    mse_re_t re;
    char *re_str = mse_escape_regex(REGEX2_ARG);
    ASSERT(re_str != NULL);
    ASSERT(mse_re_init(&re, re_str));
    free(re_str);

    mse_card_t *card = (mse_card_t *) node->payload;
    ASSERT(mse_card_oracle_matches(card, &re));

    mse_re_free(&re);
    ASSERT(test_tree_oracle_re(node->l));
    ASSERT(test_tree_oracle_re(node->r));
    return 1;
}

static int test_tree_oracle_re_negate(mse_avl_tree_node_t *node)
{
    if (node == NULL) {
        return 1;
    }

    mse_re_t re;
    char *re_str = mse_escape_regex(REGEX2_ARG);
    ASSERT(re_str != NULL);
    ASSERT(mse_re_init(&re, re_str));
    free(re_str);

    mse_card_t *card = (mse_card_t *) node->payload;
    ASSERT(!mse_card_oracle_matches(card, &re));

    mse_re_free(&re);
    ASSERT(test_tree_oracle_re_negate(node->l));
    ASSERT(test_tree_oracle_re_negate(node->r));
    return 1;
}

static int test_generator_oracle_regex()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_ORACLE_TEXT;
    size_t len = strlen(REGEX2_ARG);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_EQUALS, REGEX2_ARG, len));

    mse_search_intermediate_t inter;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > 0);
    ASSERT(test_tree_oracle_re(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // Test includes
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, REGEX2_ARG, len));
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    size_t size_1;
    ASSERT(size_1 = mse_tree_size(inter.node));
    ASSERT(test_tree_oracle_re(inter.node));
    mse_free_search_intermediate(&inter);

    // Test negate
    ret.negate = 1;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    size_t size_2;
    ASSERT(size_2 = mse_tree_size(inter.node));
    ASSERT(size_1 + size_2 == mse_tree_size(gen_cards.card_tree));

    ASSERT(test_tree_oracle_re_negate(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    return 1;
}

static int test_tree_oracle_substr(mse_avl_tree_node_t *node)
{
    if (node == NULL) {
        return 1;
    }

    mse_card_t *card = (mse_card_t *) node->payload;
    ASSERT(mse_str_match(card->oracle_text_lower, ARG_LOWER));

    ASSERT(test_tree_oracle_substr(node->l));
    ASSERT(test_tree_oracle_substr(node->r));
    return 1;
}

static int test_generator_oracle_substr()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_ORACLE_TEXT;
    size_t len = strlen(ARG);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_EQUALS, ARG, len));

    mse_search_intermediate_t inter;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > 0);
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // Test includes
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, ARG, len));
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > 0);
    ASSERT(test_tree_oracle_substr(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);
    return 1;
}

static int test_tree_name_re(mse_avl_tree_node_t *node)
{
    if (node == NULL) {
        return 1;
    }

    mse_re_t re;
    char *re_str = mse_escape_regex(REGEX_ARG);
    ASSERT(re_str != NULL);
    ASSERT(mse_re_init(&re, re_str));
    free(re_str);

    mse_card_t *card = (mse_card_t *) node->payload;
    ASSERT(mse_card_name_matches(card, &re));

    mse_re_free(&re);
    ASSERT(test_tree_name_re(node->l));
    ASSERT(test_tree_name_re(node->r));
    return 1;
}

static int test_generator_name_regex()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_NAME;
    size_t len = strlen(REGEX_ARG);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_EQUALS, REGEX_ARG, len));

    mse_search_intermediate_t inter;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > 0);
    ASSERT(test_tree_name_re(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // Test includes
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, REGEX_ARG, len));
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > 0);
    ASSERT(test_tree_name_re(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);
    return 1;
}

#define NAME_ARG "thassa, god"
#define NAME_TRIE_MIN 2

static int test_generator_name_trie()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_NAME;
    size_t len = strlen(NAME_ARG);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_EQUALS, NAME_ARG, len));

    mse_search_intermediate_t inter;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > NAME_TRIE_MIN);
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, NAME_ARG, len));
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > NAME_TRIE_MIN);
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    return 1;
}

static int test_generator_name_trie_negate()
{
    mse_set_generator_type_t gen_type = MSE_SET_GENERATOR_NAME;
    size_t len = strlen(NAME_ARG);

    mse_set_generator_t ret;
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_EQUALS, NAME_ARG, len));

    mse_search_intermediate_t inter;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    ASSERT(mse_tree_size(inter.node) > NAME_TRIE_MIN);
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // No negate
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, NAME_ARG, len));
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    size_t size_1;
    ASSERT(size_1 = mse_tree_size(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    // With negate
    ASSERT(mse_init_set_generator(&ret, gen_type, MSE_SET_GENERATOR_OP_INCLUDES, NAME_ARG, len));
    ret.negate = 1;
    ASSERT(mse_generate_set(&ret, &inter, &gen_cards));
    size_t size_2;
    ASSERT(size_2 = mse_tree_size(inter.node));
    mse_free_search_intermediate(&inter);
    mse_free_set_generator(&ret);

    ASSERT(size_1 != size_2);
    return 1;
}

SUB_TEST(test_generator_txt, {&test_generator_oracle_regex, "Test generator oraclere"},
{&test_generator_name_regex, "Test generator name re"},
{&test_generator_oracle_substr, "Test generator oracle substr"},
{&test_generator_name_trie, "Test generator name trie"},
{&test_generator_name_trie_negate, "Test generator name trie negate"})
