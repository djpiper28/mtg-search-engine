#include "./card_txt_fields_trie.h"
#include "../testing_h/testing.h"
#include "./search.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int mse_init_card_trie_node(mse_card_trie_node_t **node)
{
    *node = malloc(sizeof(**node));
    ASSERT(node != NULL);

    memset(*node, 0, sizeof(**node));
    return 1;
}

static void __mse_free_card_trie_node(mse_card_trie_node_t * restrict node)
{
    if (node == NULL) {
        return;
    }

    for (size_t i = 0; i < MSE_ALPHABET_LENGTH; i++) {
        __mse_free_card_trie_node(node->children[i]);
    }

    if (node->cards != NULL) {
        mse_free_tree(node->cards);
    }
    free(node);
}

void mse_free_card_trie_node(mse_card_trie_node_t * restrict node)
{
    __mse_free_card_trie_node(node);
}

static int __mse_card_trie_lookup(mse_card_trie_node_t * restrict root, char * restrict str, mse_avl_tree_node_t **ret, int i)
{
    if (str[i] == 0) {
        // Copy the tree
        mse_search_intermediate_t r, a, b;
        memset(&r, 0, sizeof(r));
        b = r;
        a.node = root->cards;

        ASSERT(mse_set_union(&r, &a, &b));
        *ret = r.node;
        return 1;
    }

    long c_index = mse_char_map_get_index(str[i]);

    // Fails to find
    if (root->children[c_index] == NULL) {
        return 1;
    }
    return __mse_card_trie_lookup(root->children[c_index], str, ret, i + 1);
}

int mse_card_trie_lookup(mse_card_trie_node_t * restrict trie, char * restrict str, mse_avl_tree_node_t **ret)
{
    *ret = NULL;
    char *str_f = mse_filter_text(str);
    ASSERT(str_f != NULL);
    int r = __mse_card_trie_lookup(trie, str_f, ret, 0);

    free(str_f);
    ASSERT(r);
    return 1;
}

static int __mse_insert_avl(mse_avl_tree_node_t **root, mse_avl_tree_node_t * restrict node)
{
    if (node == NULL) {
        return 1;
    }

    mse_avl_tree_node_t *node_copy = mse_shallow_copy_tree_node(node);
    ASSERT(node_copy != NULL);

    node_copy->cmp_payload = MSE_CARD_DEFAULT_COMPARE_FUNCTION;
    node_copy->free_payload = MSE_CARD_DEFAULT_FREE_FUNCTION;

    int r = mse_insert_node(root, node_copy);
    if (!r) {
        mse_free_tree(node_copy);
    }

    ASSERT(__mse_insert_avl(root, node->l));
    ASSERT(__mse_insert_avl(root, node->r));
    return 1;
}

static int __mse_insert_trie_children(mse_card_trie_node_t * restrict node, mse_avl_tree_node_t **ret)
{
    if (node == NULL) {
        return 1;
    }

    ASSERT(__mse_insert_avl(ret, node->cards));
    for (size_t i = 0; i < sizeof(node->children) / sizeof(*node->children); i++) {
        ASSERT(__mse_insert_trie_children(node->children[i], ret));
    }
    return 1;
}

static int __mse_card_trie_lookup_aprox(mse_card_trie_node_t * restrict root, char * restrict str, mse_avl_tree_node_t **ret, int i)
{
    if (str[i] == 0) {
        ASSERT(__mse_insert_trie_children(root, ret));
        return 1;
    }

    long c_index = mse_char_map_get_index(str[i]);

    // Fails to find
    if (root->children[c_index] == NULL) {
        return 1;
    }
    return __mse_card_trie_lookup_aprox(root->children[c_index], str, ret, i + 1);
}

int mse_card_trie_lookup_aprox(mse_card_trie_node_t * restrict trie, char * restrict str, mse_avl_tree_node_t **ret)
{
    *ret = NULL;
    char *str_f = mse_filter_text(str);
    ASSERT(str_f != NULL);
    int r = __mse_card_trie_lookup_aprox(trie, str_f, ret, 0);

    free(str_f);
    ASSERT(r);
    return 1;
}

static int __mse_card_trie_do_insert(mse_card_trie_node_t *root, mse_card_t * restrict card)
{
    mse_avl_tree_node_t *node = mse_init_avl_tree_node(MSE_CARD_DEFAULT_FREE_FUNCTION,
                                MSE_CARD_DEFAULT_COMPARE_FUNCTION,
                                (void *) card);
    ASSERT(node != NULL);
    if (!mse_insert_node(&root->cards, node)) {
        mse_free_tree(node);
    }
    return 1;
}

static int __mse_card_trie_insert(mse_card_trie_node_t *root, mse_card_t * restrict card, char * restrict str, int index)
{
    if (str[index] == 0) {
        return __mse_card_trie_do_insert(root, card);
    }

    long c_index = mse_char_map_get_index(str[index]);

    // Sanity checks
    ASSERT(c_index >= 0);
    ASSERT(c_index < (long) (sizeof(root->children) / sizeof(*root->children)));

    // Insert the trie node if needed
    if (root->children[c_index] == NULL) {
        ASSERT(mse_init_card_trie_node(&root->children[c_index]));
    }
    return __mse_card_trie_insert(root->children[c_index], card, str, index + 1);
}

int mse_card_trie_insert(mse_card_trie_node_t *root, mse_card_t * restrict card, char * restrict str)
{
    char *str_f = mse_filter_text(str);
    if (str_f == NULL) {
        lprintf(LOG_WARNING, "Cannot add card with name %s to the trie\n", str);
        return 1;
    }

    int r = __mse_card_trie_insert(root, card, str_f, 0);
    free(str_f);

    ASSERT(r);
    return 1;
}

#define MSE_FILTER_NO_CHAR 0

char __mse_filter_char(char c)
{
    // Unsigns your int, declines to elabourate
    size_t i = (size_t) *(unsigned char *)((void *) &c);
    return mse_filter_char_map[i];
}

static int __is_duplicate(char * restrict str, int i, char c)
{
    if (i > 0) {
        return str[i - 1] == c;
    }
    return 0;
}

char *mse_filter_text(char * restrict str)
{
    size_t len = strlen(str);
    char *ret = malloc(len + 1);
    ASSERT(ret != NULL);

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = __mse_filter_char(str[i]);
        if (c == MSE_FILTER_NO_CHAR) {
            continue;
        }

        if (__is_duplicate(ret, j, c)) {
            continue;
        }

        ret[j] = c;
        j++;
    }
    ret[j] = 0;

    // Check for empty output strings
    if (strlen(ret) == 0) {
        free(ret);
        return NULL;
    }

    return ret;
}

static int __mse_insert_to_name_parts(mse_card_name_parts_t *ret, char * restrict fname)
{
    char **tmp = realloc(ret->parts, sizeof(*ret->parts) * (ret->len + 1));
    if (tmp == NULL) {
        mse_free_card_parts(ret);
        return 0;
    }

    ret->parts = tmp;
    ASSERT(ret->parts != NULL);

    ret->parts[ret->len] = fname;
    ret->len++;
    return 1;
}

static int __mse_is_special_case(char c)
{
    switch(tolower(c)) {
    case 'a':
    case 'e':
    case 'i':
    case 'o':
    case 'u':
    case '\'':
    case '-':
    case '_':
        return 1;
    default:
        return 0;
    }
}

static int __mse_split_card_name(char * restrict name, mse_card_name_parts_t * restrict ret)
{
    char *tmp = name;
    size_t len = strlen(name);
    for (size_t i = 0; i <= len; i++) {
        if (__mse_filter_char(name[i]) != MSE_FILTER_NO_CHAR
                || __mse_is_special_case(name[i])) {
            continue;
        }

        // Insert the part
        name[i] = 0;
        char *part = mse_filter_text(tmp);
        if (part == NULL) {
            // Move the buffer ptr
            tmp = &name[i + 1];
            continue;
        }

        int r = __mse_insert_to_name_parts(ret, part);
        if (!r) {
            lprintf(LOG_ERROR, "Cannot insert name to parts struct\n");
            free(part);
            mse_free_card_parts(ret);
            return 0;
        }

        // Move the buffer ptr
        tmp = &name[i + 1];
    }
    return 1;
}

void mse_free_card_parts(mse_card_name_parts_t * restrict ret)
{
    if (ret->parts != NULL) {
        for (size_t i = 0; i < ret->len; i++) {
            if (ret->parts[i] != NULL) {
                free(ret->parts[i]);
            }
        }
        free(ret->parts);
    }
    memset(ret, 0, sizeof(*ret));
}

int mse_split_card_name(char * restrict name, mse_card_name_parts_t * restrict ret)
{
    memset(ret, 0, sizeof(*ret));

    char *tmp = strdup(name);
    ASSERT(tmp != NULL);
    int r = __mse_split_card_name(tmp, ret);
    if (!r) {
        mse_free_card_parts(ret);
    }

    free(tmp);
    ASSERT(r);
    return 1;
}
