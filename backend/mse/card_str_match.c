#include "./card_str_match.h"
#include "./io_utils.h"
#include "../testing_h/testing.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

int mse_is_regex_str(char *str)
{
    size_t len = strlen(str);
    if (len < 2) {
        return 0;
    }
    return str[0] == '/' && str[len - 1] == '/';
}

int mse_compile_regex(char *regex, mse_re_t *re)
{
    return mse_re_init(re, regex);
}

static int __mse_re_match(char *str, mse_re_t *re)
{
    return mse_re_matches(re, str);
}

#define __MSE_HASH_DEFAULT 0

int mse_str_match(char * restrict str, char * restrict substr)
{
    if (str == NULL) {
        return 0;
    }
    size_t substr_len = strlen(substr);
    long w_hash = __MSE_HASH_DEFAULT; // Window hash

    // Calculate target hash
    long substr_hash = __MSE_HASH_DEFAULT;
    for (size_t i = 0; i < substr_len; i++) {
        substr_hash += substr[i];
    }

    for (size_t i = 0; str[i] != 0; i++) {
        // Slide the window hash along
        w_hash += str[i];
        if (i >= substr_len) {
            w_hash -= str[i - substr_len];
        }

        // Check that a hash match is not a false positive
        if (w_hash == substr_hash && i + 1 >= substr_len) {
            if (memcmp(&str[i - substr_len + 1], substr, substr_len) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

int mse_card_oracle_matches(mse_card_t * restrict card, mse_re_t *re)
{
    if (card->oracle_text_lower == NULL) {
        return 0;
    }
    return __mse_re_match(card->oracle_text_lower, re);
}

int mse_card_name_matches(mse_card_t * restrict card, mse_re_t *re)
{
    if (card->name_lower == NULL) {
        return 0;
    }
    return __mse_re_match(card->name_lower, re);
}

// Code to allow for regex matching to be done in many threads
typedef enum mse_card_match_type_t {
    MSE_MATCH_ORACLE,
    MSE_MATCH_NAME
} mse_card_match_type_t;

typedef struct mse_card_match_t {
    mse_card_match_type_t type;
    mse_avl_tree_node_t **res;
    char *str;
    int negate;
    int is_regex;
} mse_card_match_t;

typedef struct mse_card_match_cmp_data_t {
    union {
        mse_re_t *re;
        char *substr;
    };
} mse_card_match_cmp_data_t;


static int __mse_match_card_do_match(mse_avl_tree_node_t * restrict node,
                                     mse_card_match_t *match_data,
                                     mse_card_match_cmp_data_t data)
{
    int matches = 0;
    switch(match_data->type) {
    case MSE_MATCH_ORACLE:
        if (match_data->is_regex) {
            matches = mse_card_oracle_matches((mse_card_t *) node->payload, data.re);
        } else {
            matches = mse_str_match(((mse_card_t *) node->payload)->oracle_text_lower, data.substr);
        }
        break;
    case MSE_MATCH_NAME:
        if (match_data->is_regex) {
            matches = mse_card_name_matches((mse_card_t *) node->payload, data.re);
        } else {
            // this is probably not going to be ussed but eh
            matches = mse_str_match(((mse_card_t *) node->payload)->name_lower, data.substr);
        }
        break;
    default:
        lprintf(LOG_ERROR, "Cannot find match type\n");
        return 0;
    }

    // Negate logic
    if (match_data->negate) {
        matches = !matches;
    }

    if (matches) {
        mse_avl_tree_node_t *node_copy = mse_shallow_copy_tree_node(node);
        if (node_copy == NULL) {
            lprintf(LOG_ERROR, "Cannot allocate tree node\n");
            return 0;
        }

        node_copy->cmp_payload = MSE_CARD_DEFAULT_COMPARE_FUNCTION;
        node_copy->free_payload = MSE_CARD_DEFAULT_FREE_FUNCTION;

        int r = mse_insert_node(match_data->res, node_copy);

        if (!r) {
            lprintf(LOG_ERROR, "Node insert failed\n");
            mse_free_tree(node_copy);
            return 0;
        }
    }

    return 1;
}

static int __mse_match_card_node(mse_avl_tree_node_t * restrict node,
                                 mse_card_match_t *match_data,
                                 mse_card_match_cmp_data_t cmp_data)
{
    if (node == NULL) {
        return 1;
    }

    ASSERT(__mse_match_card_do_match(node, match_data, cmp_data));
    ASSERT(__mse_match_card_node(node->l, match_data, cmp_data));
    ASSERT(__mse_match_card_node(node->r, match_data, cmp_data));

    return 1;
}

static int __mse_match_cards(mse_avl_tree_node_t **ret,
                             mse_avl_tree_node_t * restrict cards_tree,
                             char *str,
                             int is_regex,
                             int negate,
                             mse_card_match_type_t type)
{
    mse_re_t re;
    mse_card_match_cmp_data_t cmp_data;
    if (is_regex) {
        ASSERT(mse_compile_regex(str, &re));
        cmp_data.re = &re;
    } else {
        ASSERT(cmp_data.substr = mse_to_lower(str));
    }

    mse_card_match_t match_data;
    memset(&match_data, 0, sizeof(match_data));
    match_data.type = type;
    match_data.is_regex = is_regex;
    match_data.str = str;
    match_data.negate = negate;

    mse_avl_tree_node_t *root = NULL;
    __mse_match_card_node(root, &match_data, cmp_data);
    if (is_regex) {
        mse_re_free(&re);
    } else {
        free(cmp_data.substr);
    }

    return 1;
}

int mse_matching_card_oracle(mse_avl_tree_node_t **ret,
                             mse_avl_tree_node_t *cards_tree,
                             char *str,
                             int is_regex,
                             int negate)
{
    return __mse_match_cards(ret, cards_tree, str, is_regex, negate, MSE_MATCH_ORACLE);
}

int mse_matching_card_name(mse_avl_tree_node_t **ret,
                           mse_avl_tree_node_t *cards_tree,
                           char *str,
                           int is_regex,
                           int negate)
{
    return __mse_match_cards(ret, cards_tree, str, is_regex, negate, MSE_MATCH_NAME);
}

char *mse_escape_regex(char * restrict regex)
{
    size_t len = strlen(regex);
    ASSERT(len > 1);

    char *ret = malloc(len + 1);
    ASSERT(ret != NULL);

    size_t offset = 0;
    int escaping = regex[0] == '/' && regex[len - 1] == '/';
    if (escaping) {
        offset++;
    }

    strcpy(ret, &regex[offset]);

    if (escaping) {
        size_t r_end = len - 1 - offset;
        if (ret[r_end] == '/') {
            ret[r_end] = 0;
        }
    }

    return ret;
}
