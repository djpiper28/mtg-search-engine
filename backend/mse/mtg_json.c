#include "./mtg_json.h"
#include "./io_utils.h"
#include "./thread_pool.h"
#include "../testing_h/testing.h"
#include "card_txt_fields_trie.h"
#include "mse_formats.h"
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#ifdef _WINDOWS
#include <fcntl.h>
#include <process.h>
#include <io.h>
// Imagine if the twats at microshit had documentation
#define pipe(x) _pipe(x, 4096, O_BINARY)
#else
#include <unistd.h>
#endif

size_t __mse_json_write_callback(char *ptr,
                                 size_t size,
                                 size_t nmemb,
                                 void *data)
{
    FILE *w = (FILE *) data;
    fwrite(ptr, size, nmemb, w);
    fflush(w);
    return size * nmemb;
}

#define CURL_ASSERT(x) if ((x) != CURLE_OK) { lprintf(LOG_ERROR, "Cannot perform operation %s on cURL request\n", #x); goto curl_set_error; }
#define TEST_FLAG "MSE_TEST"

static void __do_get_all_printings_cards_curl(FILE *w)
{
    if (getenv(TEST_FLAG) != NULL) {
        lprintf(LOG_WARNING, "Test flag %s is set\n", TEST_FLAG);
        FILE *f = fopen(MSE_ALL_PRINTINGS_FILE, "r");
        if (f == NULL) {
            lprintf(LOG_ERROR, "Cannot read %s", MSE_ALL_PRINTINGS_FILE, " file\n");
            return;
        }
        for (int c; c = fgetc(f), c != EOF; fputc(c, w));
        fclose(f);
        return;
    }

    CURL *curl = curl_easy_init();
    if (curl) {
        CURLcode res = 0;

        // Set timeouts
        size_t timeout = 60 * 60 * 4; // 4 hours max download time
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout));
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L));
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout));

        // Set url, user-agent and, headers
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_URL, MSE_ATOMIC_CARDS_URL));
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_USE_SSL, 1L));
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_USERAGENT, MSE_PROJECT_NAME));
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L));
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""));

        // Set response write
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &__mse_json_write_callback));
        CURL_ASSERT(curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) w));

        res = curl_easy_perform(curl);

curl_set_error:
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            lprintf(LOG_INFO, "Finished getting atomic cards\n");
        } else {
            lprintf(LOG_ERROR, "Cannot get atomic cards\n");
        }
    } else {
        lprintf(LOG_ERROR, "Cannot init curl :(\n");
    }
}

static void __get_all_printings_cards_curl_thread(void *data, struct mse_thread_pool_t *pool)
{
    FILE *w = (FILE *) data;
    __do_get_all_printings_cards_curl(w);
    fclose(w);
}

static void __free_all_printings_cards_card(void *card)
{
    mse_free_card((mse_card_t *) card);
    free(card);
}

static void __free_all_printings_cards_set(void *set)
{
    mse_free_set((mse_set_t *) set);
    free(set);
}

int __mse_handle_all_printings_cards_set(mse_all_printings_cards_t *ret,
        const char *set_code,
        json_t *set_node)
{
    ASSERT(json_is_object(set_node));

    mse_set_t *set = malloc(sizeof(*set));
    ASSERT(set != NULL);
    ASSERT(mse_parse_set_json(set_node, set, set_code));

    mse_avl_tree_node_t *node = mse_init_avl_tree_node(&__free_all_printings_cards_set, &mse_avl_cmp_set, set);
    ASSERT(mse_insert_node(&ret->set_tree, node));

    json_t *cards = json_object_get(set_node, "cards");
    ASSERT(cards != NULL);
    ASSERT(json_is_array(cards));

    size_t index;
    json_t *value;
    json_array_foreach(cards, index, value) {
        ASSERT(json_is_object(value));
        mse_card_t *card = malloc(sizeof(*card));
        ASSERT(card != NULL);
        node = mse_init_avl_tree_node(&__free_all_printings_cards_card, &mse_avl_cmp_card, card);

        ASSERT(mse_parse_card_json(value, card));
        if (mse_insert_node(&ret->card_tree, node)) {
            ret->card_count++;
        } else {
            mse_free_tree(node);
        }
    }

    return 1;
}

int __mse_parse_all_printings_cards(mse_all_printings_cards_t *ret, json_t *cards, mse_thread_pool_t *pool)
{
    ASSERT(ret != NULL);
    memset(ret, 0, sizeof(*ret));

    // Print debug information
    json_t *meta = json_object_get(cards, "meta");
    json_t *meta_date = json_object_get(meta, "date");
    json_t *meta_version = json_object_get(meta, "version");

    ASSERT(json_is_string(meta_date));
    ASSERT(json_is_string(meta_version));

    lprintf(LOG_INFO, "Reading cards from MTGJSON (%s) released at: %s\n",
            json_string_value(meta_date),
            json_string_value(meta_version));

    // Iterate over all of the sets
    json_t *data = json_object_get(cards, "data");
    ASSERT(json_is_object(data));

    // A nice macro in jansson <3
    const char *key;
    json_t *value;
    size_t count = 0;
    json_object_foreach(data, key, value) {
        __mse_handle_all_printings_cards_set(ret, key, value);
        count++;
    }

    ret->set_count = count;
    lprintf(LOG_INFO, "Found %lu sets and, %lu cards\n", ret->set_count, ret->card_count);

    lprintf(LOG_INFO, "Generating card indexes\n");
    ASSERT(__mse_generate_indexes(ret, pool));

    lprintf(LOG_INFO, "Cards and, indexes are now complete\n");

    return 1;
}

int mse_get_all_printings_cards(mse_all_printings_cards_t *ret, mse_thread_pool_t *pool)
{
    ASSERT(ret != NULL);
    memset(ret, 0, sizeof(*ret));

    // Create the pipe that will be used for IPC
    int fid[2];
    int c = pipe(fid);
    ASSERT(c == 0);

    FILE *r = fdopen(fid[0], "r");
    ASSERT(r != NULL);

    FILE *w = fdopen(fid[1], "w");
    ASSERT(w != NULL);

    // Start curl request that writes to a pipe in another thread
    mse_task_t task = {(void *) w, &__get_all_printings_cards_curl_thread};
    ASSERT(mse_task_queue_enqueue(&pool->queue, task));

    lprintf(LOG_INFO, "Downloading cards...\n");

    // Start reading the json in this thread
    json_error_t error;
    size_t flags = 0;
    json_t *json = json_loadf(r, flags, &error);

    // If the json cannot be read due to an error, then the curl request failed, its thread should have cleared
    // that bit up
    if (json == NULL) {
        lprintf(LOG_ERROR, "Cannot parse atomic json, %100s\n", error.text);
        fclose(r);
        return 0;
    }

    // This only runs if there was no error
    int status = __mse_parse_all_printings_cards(ret, json, pool);
    json_decref(json);

    if (!status) {
        lprintf(LOG_ERROR, "Cannot parse atomic json into cards and, sets\n");
        fclose(r);
        return 0;
    }
    fclose(r);
    return 1;
}

void mse_free_colour_index(mse_colour_index_t *index)
{
    for (size_t i = 0; i < sizeof(index->colour_indexes) / sizeof(*index->colour_indexes); i++) {
        if (index->colour_indexes[i] != NULL) {
            mse_free_tree(index->colour_indexes[i]);
        }
    }
    memset(index, 0, sizeof(*index));
}

#define MSE_FREE_COLOUR_FIELD(colour_field) \
mse_free_colour_index(&cards->indexes.colour_index.colour_field##_lt); \
mse_free_colour_index(&cards->indexes.colour_index.colour_field##_lt_inc); \
mse_free_colour_index(&cards->indexes.colour_index.colour_field##_gt); \
mse_free_colour_index(&cards->indexes.colour_index.colour_field##_gt_inc); \
mse_free_colour_index(&cards->indexes.colour_index.colour_field##_eq);

static void __free_all_printings_cards_colour_indexes(mse_all_printings_cards_t *cards)
{
    MSE_FREE_COLOUR_FIELD(colours);
    MSE_FREE_COLOUR_FIELD(colour_identity);
}

static void __free_all_printings_cards_indexes(mse_all_printings_cards_t *cards)
{
    if (cards->indexes.card_power_tree != NULL) {
        mse_free_tree(cards->indexes.card_power_tree);
    }

    if (cards->indexes.card_toughness_tree != NULL) {
        mse_free_tree(cards->indexes.card_toughness_tree);
    }

    if (cards->indexes.card_cmc_tree != NULL) {
        mse_free_tree(cards->indexes.card_cmc_tree);
    }

    if (cards->indexes.card_loyalty_tree != NULL) {
        mse_free_tree(cards->indexes.card_loyalty_tree);
    }

    if (cards->indexes.card_name_parts_trie != NULL) {
        mse_free_card_trie_node(cards->indexes.card_name_parts_trie);
    }

    if (cards->indexes.card_type_trie != NULL) {
        mse_free_card_trie_node(cards->indexes.card_type_trie);
    }

    __free_all_printings_cards_colour_indexes(cards);
    mse_free_format_legality_indexes(&cards->indexes.format_legality_index);
}

void mse_free_all_printings_cards(mse_all_printings_cards_t *cards)
{
    if (cards->set_tree != NULL) {
        mse_free_tree(cards->set_tree);
    }

    if (cards->card_tree != NULL) {
        mse_free_tree(cards->card_tree);
    }

    __free_all_printings_cards_indexes(cards);
    memset(cards, 0, sizeof(*cards));
}
