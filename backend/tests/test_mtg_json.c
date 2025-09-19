#include "./test_mtg_json.h"
#include "../testing_h/testing.h"
#include "../mse/mtg_json.h"
#include "../mse/thread_pool.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>

// Some vile testing globals
static mse_thread_pool_t pool;
static mse_all_printings_cards_t test_cards;
static json_t *json;

static size_t get_tree_nodes(mse_avl_tree_node_t *node)
{
    if (node == NULL) {
        return 0;
    }
    return 1 + get_tree_nodes(node->l) + get_tree_nodes(node->r);
}

// A test for the tree props
static int test_all_printings_cards_sets_found()
{
    ASSERT(test_cards.set_tree != NULL);
    ASSERT(test_cards.set_tree->height > 0);
    ASSERT(get_tree_nodes(test_cards.set_tree) == test_cards.set_count);
    return 1;
}

static int test_all_printings_cards_found()
{
    ASSERT(test_cards.card_tree != NULL);
    ASSERT(test_cards.card_tree->height > 0);
    ASSERT(get_tree_nodes(test_cards.card_tree) == test_cards.card_count);
    return 1;
}

static int __test_card_parts_trie_index(mse_avl_tree_node_t *node)
{
    if (node == NULL) {
        return 1;
    }

    mse_card_t *card = (mse_card_t *) node->payload;
    mse_card_name_parts_t parts;
    ASSERT(mse_split_card_name(card->name, &parts));

    for (size_t i = 0; i < parts.len; i++) {
        mse_avl_tree_node_t *ret = NULL;
        ASSERT(mse_card_trie_lookup(test_cards.indexes.card_name_parts_trie, parts.parts[i], &ret));

        ASSERT(ret != NULL);
        mse_free_tree(ret);
    }
    mse_free_card_parts(&parts);

    ASSERT(__test_card_parts_trie_index(node->l));
    ASSERT(__test_card_parts_trie_index(node->r));
    return 1;
}

static int test_indexes()
{
    ASSERT(mse_tree_size(test_cards.indexes.card_power_tree) > 0);
    ASSERT(mse_tree_size(test_cards.indexes.card_toughness_tree) > 0);
    ASSERT(mse_tree_size(test_cards.indexes.card_cmc_tree) > 0);

    ASSERT(test_cards.indexes.card_name_parts_trie != NULL);
    ASSERT(__test_card_parts_trie_index(test_cards.card_tree));
    return 1;
}

SUB_TEST(__test_atomic_card_props, {&test_all_printings_cards_sets_found, "Test atomic cards found sets"},
{&test_all_printings_cards_found, "Test atomic cards found cards"},
{&test_indexes, "Test card indexes"})

// Start tests
static int init_tests()
{
    ASSERT(mse_init_pool(&pool));
    return 1;
}

static int free_tests()
{
    ASSERT(mse_free_pool(&pool));
    return 1;
}

static int test_free_all_printings_cards()
{
    mse_all_printings_cards_t ret;
    memset(&ret, 0, sizeof(ret));
    mse_free_all_printings_cards(&ret);
    return 1;
}

static int test_init_free()
{
    memset(&test_cards, 0, sizeof(test_cards));
    ASSERT(mse_get_all_printings_cards(&test_cards, &pool));

    ASSERT(test_cards.indexes.card_power_tree != NULL);
    size_t p_nodes = get_tree_nodes(test_cards.indexes.card_power_tree);
    ASSERT(p_nodes > 0);

    ASSERT(test_cards.indexes.card_toughness_tree != NULL);
    size_t t_nodes = get_tree_nodes(test_cards.indexes.card_toughness_tree);
    ASSERT(t_nodes > 0);
    ASSERT(p_nodes == t_nodes);
    ASSERT(p_nodes == test_cards.card_count);

    ASSERT(__test_atomic_card_props());
    mse_free_all_printings_cards(&test_cards);
    return 1;
}

#define TEST_TEXT "Lorem ipsum dolor sit amet, qui minim labore adipisicing minim sint cillum sint consectetur cupidatat."

static int test_curl_write_callback()
{
    int fid[2];
    ASSERT(pipe(fid) == 0);

    FILE *r = fdopen(fid[0], "rb");
    ASSERT(r != NULL);

    FILE *w = fdopen(fid[1], "wb");
    ASSERT(w != NULL);

    size_t len = sizeof(TEST_TEXT);
    ASSERT(__mse_json_write_callback(TEST_TEXT, len, 1, (void *) w) == len);
    fclose(w);

    char buffer[1024];
    ASSERT(fgets(buffer, sizeof(buffer), r) != NULL);
    fclose(r);

    ASSERT(strcmp(buffer, TEST_TEXT) == 0);
    return 1;
}

static json_t *get_all_printings_cards_from_file()
{
    FILE *f = fopen("./AllPrintings.json", "rb");
    ASSERT(f != NULL);

    json_error_t error;
    json_t *ret = json_loadf(f, 0, &error);

    if (ret == NULL) {
        lprintf(LOG_ERROR, "Error: %100s\n", error.text);
    }
    fclose(f);
    return ret;
}

static int test_parse_all_printings_cards_sets()
{
    json = get_all_printings_cards_from_file();
    ASSERT(json != NULL);

    memset(&test_cards, 0, sizeof(test_cards));
    ASSERT(__mse_parse_all_printings_cards(&test_cards, json, &pool));
    ASSERT(__test_atomic_card_props());

    mse_free_all_printings_cards(&test_cards);
    json_decref(json);
    return 1;
}

SUB_TEST(test_mse_json, {&init_tests, "Init tests"},
{&test_free_all_printings_cards, "Test free zeroed atomic cards struct"},
{&test_init_free, "Test init and, free"},
{&test_curl_write_callback, "Test cURL write callback"},
{&test_parse_all_printings_cards_sets, "Test that __mse_parse_all_printings_cards reads the sets correctly"},
{&free_tests, "Free tests"})
