#include "./mtg_json_indexes.h"
#include "../testing_h/testing.h"
#include "avl_tree.h"
#include "card_txt_fields_trie.h"
#include "testing_h/logger.h"
#include "thread_pool.h"
#include "mse_formats.h"
#include <string.h>

#define MSE_INDEX_COLOUR_NAME(colour_field, cmp_type) \
__add_card_to_##colour_field##_##cmp_type##_index

#define MSE_INDEX_COLOUR_NAME_IMPL(colour_field, cmp_type) \
__impl_add_card_to_##colour_field##_##cmp_type##_index

#define MSE_INDEX_COLOUR_NAME_IMPL_RECURSIVE(colour_field, cmp_type) \
__impl_recursive_add_card_to_##colour_field##_##cmp_type##_index

#define MSE_INDEX_COLOUR_NAME_IMPL_THREAD(colour_field, cmp_type) \
__impl_thread_add_card_to_##colour_field##_##cmp_type##_index

typedef struct mse_colour_index_generator_state_t {
    mse_avl_tree_node_t *cards;
    mse_avl_tree_node_t **tree;
    mse_colour_enum_t colours;
    int *err;
    sem_t *semaphore;
} mse_colour_index_generator_state_t;

#define MSE_INDEX_FOR_COLOUR(colour_field, cmp_type) \
static int MSE_INDEX_COLOUR_NAME_IMPL_RECURSIVE(colour_field, cmp_type) \
    (mse_avl_tree_node_t * restrict cards, \
    mse_avl_tree_node_t **tree, \
    mse_colour_enum_t colours) \
{ \
    if (cards == NULL) { \
        return 1; \
    } \
 \
    mse_card_t *card = (mse_card_t *) cards->payload; \
    if (mse_colour_##cmp_type(card->colour_field, colours)) { \
        mse_avl_tree_node_t *node = mse_init_avl_tree_node(NULL, &mse_avl_cmp_card, cards->payload); \
        ASSERT(mse_insert_node(tree, node)); \
    } \
 \
    ASSERT(MSE_INDEX_COLOUR_NAME_IMPL_RECURSIVE(colour_field, cmp_type)(cards->l, tree, colours)); \
    ASSERT(MSE_INDEX_COLOUR_NAME_IMPL_RECURSIVE(colour_field, cmp_type)(cards->r, tree, colours)); \
    return 1; \
} \
static void MSE_INDEX_COLOUR_NAME_IMPL(colour_field, cmp_type)(void *__state, mse_thread_pool_t *pool) \
{ \
    mse_colour_index_generator_state_t *gstate = (mse_colour_index_generator_state_t *) __state; \
    if (!MSE_INDEX_COLOUR_NAME_IMPL_RECURSIVE(colour_field, cmp_type)(gstate->cards, gstate->tree, gstate->colours)) { \
         *gstate->err = 0; \
    } \
    sem_post(gstate->semaphore); \
    free(gstate); \
} \
static int MSE_INDEX_COLOUR_NAME_IMPL_THREAD(colour_field, cmp_type) \
    (mse_colour_index_generator_state_t gen_state, mse_index_generator_state_t * state) \
{ \
   mse_colour_index_generator_state_t *gstate = malloc(sizeof(*gstate)); \
   ASSERT(gstate != NULL); \
   *gstate = gen_state; \
   mse_task_t task = {gstate, &MSE_INDEX_COLOUR_NAME_IMPL(colour_field, cmp_type)}; \
   if (!mse_task_queue_enqueue(&state->pool->queue, task)) { \
       free(gstate); \
       lprintf(LOG_ERROR, "Cannot enqueue colour index generator (" #colour_field "_" #cmp_type ") \n"); \
       return 0; \
   } \
   return 1; \
} \
static void MSE_INDEX_COLOUR_NAME(colour_field, cmp_type)(void *__state, mse_thread_pool_t *pool) \
{ \
    mse_index_generator_state_t *state = (mse_index_generator_state_t *) __state; \
    sem_t semaphore; \
    if (sem_init(&semaphore, 0, 0) != 0) { \
        lprintf(LOG_ERROR, "Cannot init semaphore\n"); \
        state->ret = 0; \
    } \
    int w = 0; \
    for (mse_colour_enum_t colours = 0; colours <= MSE_WUBRG; colours++) { \
        mse_colour_index_generator_state_t gen_state; \
        gen_state.cards = state->cards->card_tree; \
        gen_state.tree = &state->cards->indexes.colour_index.colour_field##_##cmp_type.colour_indexes[(size_t) colours]; \
        gen_state.colours = colours; \
        gen_state.semaphore = &semaphore; \
        gen_state.err = &state->ret; \
 \
        if (!MSE_INDEX_COLOUR_NAME_IMPL_THREAD(colour_field, cmp_type)(gen_state, state)) { \
            state->ret = 0; \
        } else { \
            w++; \
        } \
    } \
    for (int i = 0; i < w; i++) { \
        int waiting = 1; \
        while (waiting) { \
            mse_pool_try_consume(state->pool); \
            waiting = sem_trywait(&semaphore) != 0; \
        } \
    } \
    sem_destroy(&semaphore); \
    sem_post(&(state->semaphore)); \
}

#define MSE_INDEX_FOR_COLOUR_FIELD(field) \
MSE_INDEX_FOR_COLOUR(field, lt) \
MSE_INDEX_FOR_COLOUR(field, lt_inc) \
MSE_INDEX_FOR_COLOUR(field, gt) \
MSE_INDEX_FOR_COLOUR(field, gt_inc) \
MSE_INDEX_FOR_COLOUR(field, eq) \
MSE_INDEX_FOR_COLOUR(field, not_inc)

MSE_INDEX_FOR_COLOUR_FIELD(colours)
MSE_INDEX_FOR_COLOUR_FIELD(colour_identity)

#define MSE_INDEX_COLOUR_FIELD_NAME(colour_field) \
&MSE_INDEX_COLOUR_NAME(colour_field, lt), \
&MSE_INDEX_COLOUR_NAME(colour_field, lt_inc), \
&MSE_INDEX_COLOUR_NAME(colour_field, gt), \
&MSE_INDEX_COLOUR_NAME(colour_field, gt_inc), \
&MSE_INDEX_COLOUR_NAME(colour_field, eq), \
&MSE_INDEX_COLOUR_NAME(colour_field, not_inc)

// Set cards index
static int __mse_add_card_to_set(mse_card_t * restrict card, mse_avl_tree_node_t * restrict sets)
{
    for (size_t i = 0; i < card->set_codes_count; i++) {
        // Create a proxy element for the tree search as the tree will be comparing mse_set_t objects
        mse_set_t card_set_proxy;
        memcpy(card_set_proxy.code, card->set_codes[i], sizeof(card_set_proxy.code));

        mse_avl_tree_node_t *set_node = mse_find_payload(sets, &card_set_proxy);

        if (set_node != NULL) {
            mse_add_card_to_set((mse_set_t *) set_node->payload, card);
        } else {
            char set_code[MAX_SET_CODE_LEN + 1];
            set_code[MAX_SET_CODE_LEN] = 0;
            memcpy(set_code, card->set_codes[i], sizeof(card->set_codes[i]));

            lprintf(LOG_WARNING, "Cannot find set with code %s for card %s\n", set_code, card->name);
        }
    }
    return 1;
}

static int __add_cards_to_set(mse_avl_tree_node_t * restrict cards, mse_avl_tree_node_t * restrict sets)
{
    if (cards == NULL) {
        return 1;
    }

    ASSERT(__mse_add_card_to_set((mse_card_t *) cards->payload, sets));
    ASSERT(__add_cards_to_set(cards->l, sets));
    ASSERT(__add_cards_to_set(cards->r, sets));
    return 1;
}

static void __mse_generate_set_cards_index_task(void *__state, mse_thread_pool_t *pool)
{
    mse_index_generator_state_t *state = (mse_index_generator_state_t *) __state;
    if (!__add_cards_to_set(state->cards->card_tree, state->cards->set_tree)) {
        state->ret = 0;
    }
    sem_post(&(state->semaphore));
}

static int __insert_node(mse_avl_tree_node_t **root, mse_avl_tree_node_t * restrict node)
{
    if (*root == NULL) {
        *root = node;
        return 1;
    } else {
        return mse_insert_node(root, node);
    }
}

#define MSE_INDEX_FIELD_NAME(fname) __mse_generate_card_##fname##_index_task
#define MSE_INDEX_FOR_FIELD(fname) \
static int __add_cards_to_##fname##_tree(mse_avl_tree_node_t *restrict cards, mse_avl_tree_node_t **card_##fname##_tree) \
{ \
    if (cards == NULL) { \
        return 1; \
    } \
 \
    mse_avl_tree_node_t *node = mse_init_avl_tree_node(NULL, &mse_avl_cmp_card_##fname, cards->payload); \
    int r = __insert_node(card_##fname##_tree, node); \
    if (!r) { \
        lprintf(LOG_ERROR, "Cannot insert a card into the " #fname " tree\n"); \
        mse_free_tree(node); \
        return 0; \
    } \
    ASSERT(__add_cards_to_##fname##_tree(cards->l, card_##fname##_tree)); \
    ASSERT(__add_cards_to_##fname##_tree(cards->r, card_##fname##_tree)); \
    return 1; \
} \
static void MSE_INDEX_FIELD_NAME(fname)(void *__state, mse_thread_pool_t *pool) \
{ \
    mse_index_generator_state_t *state = (mse_index_generator_state_t *) __state; \
    if (!__add_cards_to_##fname##_tree(state->cards->card_tree,  \
                                      &state->cards->indexes.card_##fname##_tree)) { \
        state->ret = 0; \
    } \
    sem_post(&(state->semaphore)); \
}

MSE_INDEX_FOR_FIELD(power)
MSE_INDEX_FOR_FIELD(toughness)
MSE_INDEX_FOR_FIELD(cmc)
MSE_INDEX_FOR_FIELD(loyalty)

static int __add_cards_to_card_type_trie(mse_avl_tree_node_t * restrict node, mse_card_trie_node_t * restrict card_type_trie)
{
    if (node == NULL) {
        return 1;
    }

    mse_card_t *card = (mse_card_t *) node->payload;
    for (size_t i = 0; i < card->types_count; i++) {
        ASSERT(mse_card_trie_insert(card_type_trie, card, card->types[i]));
    }

    ASSERT(__add_cards_to_card_type_trie(node->l, card_type_trie));
    ASSERT(__add_cards_to_card_type_trie(node->r, card_type_trie));
    return 1;
}

static void __mse_generate_card_type_trie_task(void *__state, mse_thread_pool_t *pool)
{
    mse_index_generator_state_t *state = (mse_index_generator_state_t *) __state;
    if (!__add_cards_to_card_type_trie(state->cards->card_tree, state->cards->indexes.card_type_trie)) {
        state->ret = 0;
    }
    sem_post(&(state->semaphore));
}

static int __add_cards_to_card_name_parts_trie(mse_avl_tree_node_t * restrict node,
        mse_card_trie_node_t * restrict card_name_parts_trie)
{
    if (node == NULL) {
        return 1;
    }

    mse_card_t *card = (mse_card_t *) node->payload;
    mse_card_name_parts_t parts;
    ASSERT(mse_split_card_name(card->name, &parts));

    int r = 1;
    for (size_t i = 0; i < parts.len; i++) {
        r = mse_card_trie_insert(card_name_parts_trie, card, parts.parts[i]);
        if (!r) {
            break;
        }
    }
    mse_free_card_parts(&parts);
    ASSERT(r);

    ASSERT(__add_cards_to_card_name_parts_trie(node->l, card_name_parts_trie));
    ASSERT(__add_cards_to_card_name_parts_trie(node->r, card_name_parts_trie));
    return 1;
}

static void __mse_generate_card_name_parts_trie_task(void *__state, mse_thread_pool_t *pool)
{
    mse_index_generator_state_t *state = (mse_index_generator_state_t *) __state;
    if (!__add_cards_to_card_name_parts_trie(state->cards->card_tree,
            state->cards->indexes.card_name_parts_trie)) {
        state->ret = 0;
    }
    sem_post(&(state->semaphore));
}

static void __mse_generate_format_legalities_task(void *__state, mse_thread_pool_t *pool)
{

    mse_index_generator_state_t *state = (mse_index_generator_state_t *) __state;
    if (!mse_generate_format_legality_indexes(state->cards->card_tree,
            &state->cards->indexes.format_legality_index,
            pool)) {
        state->ret = 0;
    }
    sem_post(&(state->semaphore));
}

#define TASK_COUNT(T) (sizeof(T) / sizeof(*T))

int __mse_generate_indexes(mse_all_printings_cards_t * restrict ret, mse_thread_pool_t *pool)
{
    ASSERT(pool != NULL);
    ASSERT(ret != NULL);
    ASSERT(mse_init_card_trie_node(&ret->indexes.card_name_parts_trie));
    ASSERT(mse_init_card_trie_node(&ret->indexes.card_type_trie));

    void (*tasks[])(void *, struct mse_thread_pool_t *) = {
        &__mse_generate_set_cards_index_task,
        &__mse_generate_card_name_parts_trie_task,
        &__mse_generate_card_type_trie_task,
        &__mse_generate_format_legalities_task,
        &MSE_INDEX_FIELD_NAME(power),
        &MSE_INDEX_FIELD_NAME(toughness),
        &MSE_INDEX_FIELD_NAME(cmc),
        &MSE_INDEX_FIELD_NAME(loyalty),
        MSE_INDEX_COLOUR_FIELD_NAME(colours),
        MSE_INDEX_COLOUR_FIELD_NAME(colour_identity)
    };

    mse_index_generator_state_t state;
    state.ret = 1;
    state.cards = ret;
    state.pool = pool;
    ASSERT(sem_init(&state.semaphore, 0, 0) == 0);

    // Start the tasks
    size_t len = TASK_COUNT(tasks);
    lprintf(LOG_INFO, "Generating %lu indexes\n", len
            // Colour and colour identity indexes
            + (32 * 7 * 2)
            // Format legality indexes
            + (MSE_FORMAT_END * MSE_FORMAT_LEGALITIES_END)
           );

    for (size_t i = 0; i < len; i++) {
        mse_task_t task = {(void *) &state, tasks[i]};
        ASSERT(mse_task_queue_enqueue(&pool->queue, task));
    }

    // Wait for all of the tasks to complete on the thread pool
    for (size_t i = 0; i < TASK_COUNT(tasks); i++) {
        sem_wait(&state.semaphore);
    }
    int tmp = state.ret;
    mse_free_index_generator_state(&state);

    ASSERT(tmp);
    return 1;
}

void mse_free_index_generator_state(mse_index_generator_state_t *state)
{
    sem_destroy(&state->semaphore);
    memset(state, 0, sizeof(*state));
}
