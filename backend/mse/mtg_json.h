#pragma once
#include "./thread_pool.h"
#include "./card.h"
#include "./set.h"
#include "./avl_tree.h"
#include "./card_txt_fields_trie.h"
#include "mse_formats.h"
#include <jansson.h>

#define MSE_ATOMIC_CARDS_URL "https://mtgjson.com/api/v5/AllPrintings.json"
#define MSE_ALL_PRINTINGS_FILE "AllPrintings.json"

/// Exposed internal method for use within internal testing
size_t __mse_json_write_callback(char *ptr,
                                 size_t size,
                                 size_t nmemb,
                                 void *data);

#define MSE_COLOUR_INDEX_MAX_CARDS (MSE_WUBRG + 1)

/// The indexes for the cards which are in a large list and sorted by
/// the bit flags from 00000 to 11111
typedef struct mse_colour_index_t {
    mse_avl_tree_node_t * colour_indexes[MSE_COLOUR_INDEX_MAX_CARDS];
} mse_colour_index_t;

void mse_free_colour_index(mse_colour_index_t *index);

#define MSE_COLOUR_INDEX_GENERATOR(index_base_name) \
mse_colour_index_t index_base_name##_lt; \
mse_colour_index_t index_base_name##_lt_inc; \
mse_colour_index_t index_base_name##_gt; \
mse_colour_index_t index_base_name##_gt_inc; \
mse_colour_index_t index_base_name##_eq; \
mse_colour_index_t index_base_name##_not_inc;

/// Holds all of the colour indexes
typedef struct mse_cards_colours_indexes_t {
    MSE_COLOUR_INDEX_GENERATOR(colours)
    MSE_COLOUR_INDEX_GENERATOR(colour_identity)
} mse_cards_colours_indexes_t;

/// Contains all of the card indexes, each index will have a payload that is a pointer to a card,
/// however it will have a NULL free pointer as the memory is owneed by mse_all_printings_cards_t
/// in card_tree
typedef struct mse_cards_indexes_t {
    /// Index for power
    mse_avl_tree_node_t *card_power_tree;
    /// Index for toughness
    mse_avl_tree_node_t *card_toughness_tree;
    /// Index for card cmc
    mse_avl_tree_node_t *card_cmc_tree;
    /// Index for planeswalker loyality
    mse_avl_tree_node_t *card_loyalty_tree;
    /// Card names parts trie where the filtered name is used (a part being something white space seperated "goblin" "moviator")
    mse_card_trie_node_t *card_name_parts_trie;
    /// Card type trie where each filtered type is used
    mse_card_trie_node_t *card_type_trie;

    /// Colours index, this is a long list of stuff
    mse_cards_colours_indexes_t colour_index;

    /// Format legality index, this is a long list of stuff,
    /// see "mse_formats.h"
    mse_format_legality_indexes_t format_legality_index;
} mse_cards_indexes_t;

/// This will store the atomic cards and, sets. Each card is stored once and,
/// only once. cards and, sets are both stored as binary trees sorted by UUIDs.
/// other indices need to be generated afterwards.
typedef struct mse_all_printings_cards_t {
    /// Amount of sets
    size_t set_count;
    /// AVL BST tree for the sets, sorted by set code
    mse_avl_tree_node_t *set_tree;

    /// Amount of cards
    size_t card_count;
    /// AVL BST tree for the cards, sorted by UUID
    mse_avl_tree_node_t *card_tree;

    /// Indexes
    mse_cards_indexes_t indexes;
} mse_all_printings_cards_t;

/// Exposed internal method for use within internal testing
/// This function will handle a set node and add the set and, cards
int __mse_handle_all_printings_cards_set(mse_all_printings_cards_t *ret,
        const char *set_code,
        json_t *set_node);

/// Exposed internal method for use within internal testing
/// This method will parse the json cards all of the indexes
int __mse_parse_all_printings_cards(mse_all_printings_cards_t *ret, json_t *cards, mse_thread_pool_t *pool);

/// Returns 1 on success, 0 on failure
/// Do not call mse_free_all_printings_cards on fail
int mse_get_all_printings_cards(mse_all_printings_cards_t *ret, mse_thread_pool_t *pool);

/// This function will generate all of the indexes for a card, defined in mse_json_indexes.c
int __mse_generate_indexes(mse_all_printings_cards_t *ret, mse_thread_pool_t *pool);

/// Frees atomic cards
void mse_free_all_printings_cards(mse_all_printings_cards_t *cards);
