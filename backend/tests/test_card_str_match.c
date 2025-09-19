#include "./test_card_str_match.h"
#include "../testing_h/testing.h"
#include "../mse/card_str_match.h"
#include "../mse/save.h"
#include <stdio.h>
#include <string.h>

// Some vile testing globals
static mse_all_printings_cards_t test_cards;
static mse_thread_pool_t pool;

static int init_test_cards()
{
    ASSERT(mse_init_pool(&pool));
    ASSERT(mse_get_cards_from_file(&test_cards, &pool));
    ASSERT(test_cards.card_tree != NULL);
    return 1;
}

static int free_test_card()
{
    ASSERT(mse_free_pool(&pool));
    mse_free_all_printings_cards(&test_cards);
    return 1;
}

#define ORACLE_TEST_REGEX_1_MATCHES 21
#define ORACLE_TEST_REGEX_1 ".*whenever a (creature|enchantment) enters.*"
#define ORACLE_TEST_REGEX_2_MATHCES 59
#define ORACLE_TEST_REGEX_2 "whenever .* enters,.*draw (a|[0-9]+) cards?.*"

static int test_card_matches()
{
    mse_re_t re;
    ASSERT(mse_re_init(&re, ORACLE_TEST_REGEX_1));

    mse_card_t card;
    card.name = "Testing name 123";
    card.name_lower = "testing name 123";
    card.oracle_text = "Whenever a creature enters, pass go and collect $200.";
    card.oracle_text_lower = "whenever a creature enters, pass go and collect $200.";

    for (size_t i = 0; i < 100; i++) {
        ASSERT(mse_card_oracle_matches(&card, &re));
        ASSERT(!mse_card_name_matches(&card, &re));
    }
    mse_re_free(&re);
    return 1;
}

static int test_oracle_match()
{
    mse_avl_tree_node_t *ret = NULL;
    ASSERT(mse_matching_card_oracle(&ret, test_cards.card_tree, ORACLE_TEST_REGEX_1, 1, 0));
    ASSERT(ret != NULL);
    ASSERT(mse_tree_size(ret) >= ORACLE_TEST_REGEX_1_MATCHES);
    mse_free_tree(ret);
    return 1;
}

static int test_oracle_match_2()
{
    mse_avl_tree_node_t *ret = NULL;
    ASSERT(mse_matching_card_oracle(&ret, test_cards.card_tree, ORACLE_TEST_REGEX_2, 1, 0));
    ASSERT(ret != NULL);
    ASSERT(mse_tree_size(ret) >= ORACLE_TEST_REGEX_2_MATHCES);
    mse_free_tree(ret);
    return 1;
}

static int test_oracle_match_3()
{
    mse_avl_tree_node_t *ret = NULL;
    ASSERT(mse_matching_card_oracle(&ret, test_cards.card_tree, ORACLE_TEST_REGEX_2, 1, 1));
    ASSERT(ret != NULL);
    ASSERT(mse_tree_size(ret) >= ORACLE_TEST_REGEX_2_MATHCES);
    mse_free_tree(ret);
    return 1;
}

#define NAME_TEST_REGEX_1_MATCHES 29
#define NAME_TEST_REGEX_1 ".*, god of .*"
#define NAME_TEST_REGEX_2_MATHCES 17
#define NAME_TEST_REGEX_2 ".* class$"

static int test_name_match()
{
    mse_avl_tree_node_t *ret = NULL;
    ASSERT(mse_matching_card_name(&ret, test_cards.card_tree, NAME_TEST_REGEX_1, 1, 0));
    ASSERT(ret != NULL);
    ASSERT(mse_tree_size(ret) >= NAME_TEST_REGEX_1_MATCHES);
    mse_free_tree(ret);
    return 1;
}

static int test_name_match_2()
{
    mse_avl_tree_node_t *ret = NULL;
    ASSERT(mse_matching_card_name(&ret, test_cards.card_tree, NAME_TEST_REGEX_2, 1, 0));
    ASSERT(ret != NULL);
    ASSERT(mse_tree_size(ret) >= NAME_TEST_REGEX_2_MATHCES);
    mse_free_tree(ret);
    return 1;
}

#define INVALID_RE "("

static int test_regex_compile_err()
{
    mse_re_t re;
    ASSERT(!mse_re_init(&re, INVALID_RE));
    mse_re_free(&re);
    return 1;
}

static int test_oracle_match_a_lot_of_times()
{
    // On my machine it took 50 seconds for 10,000 this is probably fine
    for (size_t i = 0; i < 100; i++) {
        ASSERT(test_name_match());
    }
    return 1;
}

#define NO_REPLACEMENT_STR "abcdefgh/"
#define STRIPPED_STR "test132123123(abc)+"
#define STRIP_STR "/" STRIPPED_STR "/"

#define ESCAPED_SLASH "/1/1/"

static int test_regex_escape()
{
    char *tmp = mse_escape_regex(NO_REPLACEMENT_STR);
    ASSERT(tmp != NULL);
    ASSERT(strcmp(tmp, NO_REPLACEMENT_STR) == 0);
    free(tmp);

    tmp = mse_escape_regex(STRIP_STR);
    ASSERT(tmp != NULL);
    ASSERT(strcmp(tmp, STRIPPED_STR) == 0);
    free(tmp);

    tmp = mse_escape_regex(ESCAPED_SLASH);
    ASSERT(tmp != NULL);
    ASSERT(strcmp("1/1", tmp) == 0);
    free(tmp);
    return 1;
}

#define TARGET_STR "Lorem ipsum dolor sit amet, qui minim labore adipisicing minim sint cillum sint consectetur cupidatat."

static int test_str_match()
{
    ASSERT(mse_str_match(TARGET_STR, TARGET_STR));
    ASSERT(mse_str_match("abc" TARGET_STR, TARGET_STR));
    ASSERT(mse_str_match(TARGET_STR "abc", TARGET_STR));
    ASSERT(mse_str_match("abc" TARGET_STR "abc", TARGET_STR));

    ASSERT(mse_str_match("{T}: Target creature gains haste.", "haste"));
    ASSERT(mse_str_match("First strike Whenever a creature dealt damage by Abattoir Ghoul this turn dies, you gain life equal to that creature’s toughness.", "Whenever a creature"));

    ASSERT(!mse_str_match("abc", TARGET_STR));
    ASSERT(!mse_str_match("abc", "def"));
    ASSERT(!mse_str_match(NULL, "def"));
    return 1;
}

static int test_oracle_match_substr()
{
    mse_avl_tree_node_t *ret = NULL;
    ASSERT(mse_matching_card_oracle(&ret, test_cards.card_tree, "WhEnEvEr A cReature", 0, 0));
    ASSERT(ret != NULL);
    lprintf(LOG_INFO, "There are %lu nodes\n", mse_tree_size(ret));
    ASSERT(mse_tree_size(ret) >= 418);
    mse_free_tree(ret);
    return 1;
}

SUB_TEST(test_card_str_match, {&init_test_cards, "Init regex test cards"},
{&test_card_matches, "Test card matches"},
{&test_oracle_match, "Test oracle regex match"},
{&test_oracle_match_2, "Test oracle regex match 2"},
{&test_oracle_match_3, "Test oracle regex match 2 (negate test)"},
{&test_name_match, "Test name regex match"},
{&test_name_match_2, "Test name regex match 2"},
{&test_regex_compile_err, "Test regex compile error case"},
{&test_oracle_match_a_lot_of_times, "Test oracle match a lot of times"},
{&test_regex_escape, "Test regex escape"},
{&test_str_match, "Test str match"},
{&test_oracle_match_substr, "Test oracle match substr"},
{&free_test_card, "Free regex test cards"})
