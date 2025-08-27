#pragma once
#include "./generators.h"
#include "./avl_tree.h"
#include "./mtg_json.h"

int mse_generate_set_power(mse_set_generator_t *gen,
                           mse_search_intermediate_t *res,
                           mse_all_printings_cards_t *cards);

int mse_generate_set_toughness(mse_set_generator_t *gen,
                               mse_search_intermediate_t *res,
                               mse_all_printings_cards_t *cards);

int mse_generate_set_cmc(mse_set_generator_t *gen,
                         mse_search_intermediate_t *res,
                         mse_all_printings_cards_t *cards);

int mse_generate_set_loyalty(mse_set_generator_t *gen,
                             mse_search_intermediate_t *res,
                             mse_all_printings_cards_t *cards);
