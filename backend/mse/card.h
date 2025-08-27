#pragma once
#include <stdio.h>
#include <stddef.h>
#include <limits.h>
#include <jansson.h>
#include "./uuid.h"
#include "mse_formats.h"

typedef enum mse_colour_enum_t {
    MSE_WHITE  = 1 << 0,
    MSE_BLUE   = 1 << 1,
    MSE_BLACK  = 1 << 2,
    MSE_RED    = 1 << 3,
    MSE_GREEN  = 1 << 4
} mse_colour_enum_t;

#define MSE_WUBRG 0x1F

mse_colour_enum_t mse_parse_colour(char colour);

/// This will parse a card's mana cost or, a colour,
/// 4{W}{U} will return MSE_BLUE | MSE_WHITE
/// W will return MSE_WHITE
mse_colour_enum_t mse_parse_colours(const char *colours);

#define MTG_SPECIAL_NUMERICAL_VAL NAN

typedef struct mse_card_t {
    mse_uuid_t id;
    char *name;
    char *name_lower;
    char *mana_cost;
    char *oracle_text;
    char *oracle_text_lower;
    size_t types_count;
    char **types;
    float power;
    float toughness;
    float cmc;
    mse_colour_enum_t colours;
    mse_colour_enum_t colour_identity;
    size_t set_codes_count;
    mse_set_code_t *set_codes;
    mse_card_format_legalities_t format_legalities;
    /// 0 is no loyality
    float loyalty;
    /// Contains all of the cards information in JSON already, for use with APIs
    json_t *json;
} mse_card_t;

/// As this is a library to search cards all the trees that this uses are trees whose payloads are cards.
#define MSE_CARD_DEFAULT_COMPARE_FUNCTION &mse_avl_cmp_card
#define MSE_CARD_DEFAULT_FREE_FUNCTION NULL

int mse_parse_card_json(json_t *json, mse_card_t *card);
int mse_write_card(FILE *f, mse_card_t card);
int mse_read_card(FILE *f, mse_card_t *card);

void mse_free_card(mse_card_t *card);

// Indexes comparison functions
int mse_avl_cmp_card(void *a, void *b);
int mse_avl_cmp_card_name(void *a, void *b);
int mse_avl_cmp_card_power(void *a, void *b);
int mse_avl_cmp_card_toughness(void *a, void *b);
int mse_avl_cmp_card_cmc(void *a, void *b);
int mse_avl_cmp_card_loyalty(void *a, void *b);

// Pop count on Microshit Windoze
#ifdef _MSC_VER
#  include <intrin.h>
#  define __builtin_popcount __popcnt
#endif

/// Checks that a has the same colours of b at a minimum
#define __mse_has_colours(a, b) \
(__builtin_popcount((a) & (b)) == __builtin_popcount((b)))

/// Checks that b has a subset of colours of a
#define __mse_has_subset_colours(a, b) \
(__builtin_popcount((a) & (b)) <= __builtin_popcount(b) && __builtin_popcount((a) & ~(b) & MSE_WUBRG) == 0)

#define mse_colour_lt(a, b) \
(__builtin_popcount((a)) < __builtin_popcount((b)) && __mse_has_subset_colours(a, b))

#define mse_colour_lt_inc(a, b) \
(__builtin_popcount((a)) <= __builtin_popcount((b)) && __mse_has_subset_colours(a, b))

#define mse_colour_gt(a, b) \
(__builtin_popcount((a)) > __builtin_popcount((b)) && __mse_has_colours(a, b))

#define mse_colour_gt_inc(a, b) \
(__builtin_popcount((a)) >= __builtin_popcount((b)) && __mse_has_colours(a, b))

#define mse_colour_eq(a, b) \
((a) == (b))

#define mse_colour_not_inc(a, b) \
(__builtin_popcount((a) & (b)) == 0)
