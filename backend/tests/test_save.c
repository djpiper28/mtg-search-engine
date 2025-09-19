#include "./test_save.h"
#include "../testing_h/testing.h"
#include "../mse/save.h"
#include <string.h>
#include <unistd.h>

#define MIN_CARDS 23000

static int test_init_save()
{
    if (remove(MSE_CARDS_FILE_NAME)) {
        lprintf(LOG_WARNING, "Cannot deleted save file, this may cause errors, it may not even exist, either way it might be fine\n");
    }

    mse_thread_pool_t pool;
    ASSERT(mse_init_pool(&pool));

    mse_all_printings_cards_t cards;
    memset(&cards, 0, sizeof(cards));
    ASSERT(!mse_get_cards_from_file(&cards, &pool));

    mse_free_all_printings_cards(&cards);
    mse_free_pool(&pool);
    return 1;
}

static mse_all_printings_cards_t test_cards;

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

SUB_TEST(__test_atomic_card_props_save, {&test_all_printings_cards_sets_found, "Test atomic cards found sets"},
{&test_all_printings_cards_found, "Test atomic cards found cards"},
{&test_indexes, "Test card indexes"})

static int test_get_and_save_cards()
{
    mse_thread_pool_t pool;
    ASSERT(mse_init_pool(&pool));

    mse_all_printings_cards_t cards;
    memset(&cards, 0, sizeof(cards));
    ASSERT(mse_get_all_printings_cards(&cards, &pool));

    lprintf(LOG_INFO, "Saving cards...\n");
    FILE *f = fopen(MSE_CARDS_FILE_NAME, "wb");
    ASSERT(f != NULL);
    ASSERT(mse_write_cards(f, &cards));
    fclose(f);

    test_cards = cards;
    ASSERT(__test_atomic_card_props_save());

    mse_free_all_printings_cards(&cards);
    mse_free_pool(&pool);
    return 1;
}

static int test_save_after_init()
{
    FILE *f = fopen(MSE_CARDS_FILE_NAME, "rb");
    ASSERT(f != NULL);
    fclose(f);

    mse_thread_pool_t pool;
    ASSERT(mse_init_pool(&pool));

    mse_all_printings_cards_t cards;
    memset(&cards, 0, sizeof(cards));
    ASSERT(mse_get_cards_from_file(&cards, &pool));

    ASSERT(mse_tree_size(cards.card_tree) > MIN_CARDS);
    test_cards = cards;
    ASSERT(__test_atomic_card_props_save());

    mse_free_all_printings_cards(&cards);
    mse_free_pool(&pool);
    return 1;
}

static int test_version_number()
{
    ASSERT(MSE_BINARY_VERSION != 0);
    return 1;
}

SUB_TEST(test_save, {&test_init_save, "Test init save"},
{&test_get_and_save_cards, "Test get and save cards"},
{&test_save_after_init, "Test save after init"},
{&test_version_number, "Test binary version number"})
