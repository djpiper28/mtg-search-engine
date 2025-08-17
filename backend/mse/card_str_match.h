#pragma once
#include "./avl_tree.h"
#include "./card.h"
#include "./re2_wrapper.h"

/// A fast method to find if a string matches another
int mse_str_match(char *str, char *substr);

/// Returns whether or no a string is a regex string
/// /abc/ is a regex string, otherwise it would be a normal string
int mse_is_regex_str(char *str);

/// Helper to use the correct flags for the regex, use regfree on your regex afterwards
int mse_compile_regex(char *regex, mse_re_t *re);

/// Returns 1 if there are one or matches in the oracle for the regex
int mse_card_oracle_matches(mse_card_t *card, mse_re_t *re);

/// Returns 1 if there are one or matches in the name for the regex
int mse_card_name_matches(mse_card_t *card, mse_re_t *re);

/// Returns a set of matching cards for an oracle regex
int mse_matching_card_oracle(mse_avl_tree_node_t **ret,
                             mse_avl_tree_node_t *cards_tree,
                             char *str,
                             int is_regex,
                             int negate);

/// Returns a set of matching cards for a name regex
int mse_matching_card_name(mse_avl_tree_node_t **ret,
                           mse_avl_tree_node_t *cards_tree,
                           char *str,
                           int is_regex,
                           int negate);

/// The syntax for the langugage wraps regex in slashes, these will be removed by calling this
/// Takes a regex string i.e:
/// abc\\/bcdef -> abc\/bcdef
/// /test123/ -> test123
char *mse_escape_regex(char *regex);
