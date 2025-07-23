#include "./server.h"
#include <jansson.h>
#include <mse_formats.h>
#include <testing_h/testing.h>
#include <mongoose/mongoose.h>
#include <mse/search.h>
#include <mse/async_query.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#define MIN(a, b) (a < b ? a : b)
#define BILLION ((double) 1000000000L)

// Server state, this is global as there is only every one server
static mse_t *mse = NULL;
static size_t requests = 0;
static size_t good_requests = 0;
static size_t internal_error_requests = 0;
static size_t user_error_requests = 0;
static size_t queries = 0;
static size_t card_lookups = 0;
static double total_query_time = 0;

static int __mse_get_page_number(struct mg_http_message *hm)
{
    int res = 0;
    struct mg_str *header = mg_http_get_header(hm, "page");
    if (header == NULL) {
        return 0;
    }

    char buffer[10];
    memset(buffer, 0, sizeof(buffer));
    strncpy(buffer, header->buf, MIN(sizeof(buffer), header->len));

    res = atoi(buffer);
    ASSERT(res >= 0);
    ASSERT(res >= 0);
    return res;
}

static int __mse_get_sort(struct mg_http_message *hm)
{
    int res = 0;
    struct mg_str *header = mg_http_get_header(hm, "sort");
    if (header == NULL) {
        return 0;
    }

    char buffer[10];
    memset(buffer, 0, sizeof(buffer));
    strncpy(buffer, header->buf, MIN(sizeof(buffer), header->len));

    res = atoi(buffer);
    ASSERT(res >= 0);
    ASSERT(res <= MSE_SORT_END);
    return res;
}

static int __mse_get_sort_asc(struct mg_http_message *hm)
{
    int res = 0;
    struct mg_str *header = mg_http_get_header(hm, "sort_asc");
    if (header == NULL) {
        return 0;
    }

    char buffer[10];
    memset(buffer, 0, sizeof(buffer));
    strncpy(buffer, header->buf, MIN(sizeof(buffer), header->len));

    res = atoi(buffer);
    ASSERT(res >= 0);
    ASSERT(res <= 1);
    return res;
}

static void __mse_serve_index(struct mg_connection *c,
                              int event,
                              void *ev_data)
{
    mg_http_reply(c,
                  200,
                  "",
                  "<h1>To use this API POST to ./api where the body is the query. Set the 'page' header to the page of output you want.</h1>"
                  "<a href='/github'>%s %s</a>",
                  MSE_PROJECT_NAME,
                  MSE_PROJECT_VERSION);
    good_requests++;
}

static void __mse_serve_api(struct mg_connection *c,
                            int event,
                            void *ev_data)
{
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    if (hm->body.len == 0) {
        mg_http_reply(c, 400, "", "400 - Empty request body");
        user_error_requests++;
        return;
    }

    char *query = malloc(hm->body.len + 1);
    if (query == NULL) {
        lprintf(LOG_ERROR, "Cannot alloc query string\n");
        mg_http_reply(c, 500, "", "500 - Internal server error");
        internal_error_requests++;
        return;
    }

    strncpy(query, hm->body.buf, hm->body.len);
    query[hm->body.len] = 0;

    int page_number = __mse_get_page_number(hm);
    int sort = __mse_get_sort(hm);
    int sort_asc = __mse_get_sort_asc(hm);

    mse_query_params_t params;
    params.page_number = page_number;
    params.sort = sort;
    params.sort_asc = sort_asc;

    if (!(c->fn_data = mse_start_async_query(query, params, mse))) {
        lprintf(LOG_ERROR, "Cannot start async query\n");
        mg_http_reply(c, 500, "", "500 - Internal server error");
        internal_error_requests++;
    }
}

static void __mse_serve_card_by_id(struct mg_connection *c,
                                   int event,
                                   void *ev_data)
{
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    if (hm->body.len == 0) {
        mg_http_reply(c, 400, "", "400 - Empty request body");
        user_error_requests++;
        return;
    }

    char *id = malloc(hm->body.len + 1);
    if (id == NULL) {
        lprintf(LOG_ERROR, "Cannot alloc id string\n");
        mg_http_reply(c, 500, "", "500 - Internal server error");
        internal_error_requests++;
        return;
    }

    strncpy(id, hm->body.buf, hm->body.len);
    id[hm->body.len] = 0;

    mse_card_t *card = NULL;
    int success = mse_card_by_id(mse, id, &card);
    free(id);

    if (!success) {
        lprintf(LOG_ERROR, "Cannot lookup card by id: %s", id);
        mg_http_reply(c, 500, "", "500 - Internal server error");
        internal_error_requests++;
        return;
    }

    char *json = json_dumps(card->json, 0);
    if (json != NULL) {
        mg_http_reply(c, 200, "", "%s", json);
        card_lookups++;
        good_requests++;
        free(json);
    } else {
        lprintf(LOG_ERROR, "Cannot lookup card by id: %s", id);
        mg_http_reply(c, 500, "", "500 - Internal server error");
        internal_error_requests++;
    }
}

static void __mse_serve_github(struct mg_connection *c,
                               int event,
                               void *ev_data)
{
    mg_http_reply(c, 301, "",
                  "<meta http-equiv=\"refresh\" content=\"0; URL=%s\" />",
                  MSE_REPO_URL);
    good_requests++;
}

static void __mse_serve_metrics(struct mg_connection *c,
                                int event,
                                void *ev_data)
{
    mg_http_reply(c, 200, "", "mse_requests %lu\nmse_good_requests %lu\nmse_interal_error_requests %lu\nmse_user_error_requests %lu\nmse_total_queries %lu\nmse_total_query_time_s %lf\nmse_total_card_lookups %lu",
                  requests,
                  good_requests,
                  internal_error_requests,
                  user_error_requests,
                  queries,
                  total_query_time,
                  card_lookups);
    good_requests++;
}

static void __mse_serve(struct mg_connection *c,
                        int event,
                        void *ev_data)
{
    if (event == MG_EV_ACCEPT) {
        c->fn_data = NULL;
    } else if (event == MG_EV_HTTP_MSG) {
        requests++;

        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_match(hm->uri, mg_str("/api"), NULL)) {
            __mse_serve_api(c, event, ev_data);
        } else if (mg_match(hm->uri, mg_str("/card_id"), NULL)) {
            __mse_serve_card_by_id(c, event, ev_data);
        } else if (mg_match(hm->uri, mg_str("/"), NULL)) {
            __mse_serve_index(c, event, ev_data);
        } else if (mg_match(hm->uri, mg_str("/github"), NULL)) {
            __mse_serve_github(c, event, ev_data);
        } else if (mg_match(hm->uri, mg_str("/formats"), NULL)) {
            mg_http_reply(c, 200, "", MSE_FORMATS_JSON);
            good_requests++;
        } else if (mg_match(hm->uri, mg_str("/metrics"), NULL)) {
            __mse_serve_metrics(c, event, ev_data);
        } else {
            mg_http_reply(c, 404, "", "404 - Page not found");
            user_error_requests++;
        }
    } else if (event == MG_EV_POLL && c->is_accepted && c->fn_data != NULL) {
        mse_async_query_t *query = (mse_async_query_t *) c->fn_data;
        if (!mse_async_query_poll(query)) {
            return;
        }

        if (query->err || query->resp == NULL) {
            lprintf(LOG_ERROR, "Cannot get the response err=%d, resp=%s\n", query->err, query->resp);
            mg_http_reply(c, 500, "", "500 - Internal server error");
            internal_error_requests++;
        }
        mg_http_reply(c, 200, "", "%s", query->resp);

        good_requests++;
        queries++;

        double query_time = (query->stop.tv_sec - query->start.tv_sec)
                            + (double) (query->stop.tv_nsec - query->start.tv_nsec)
                            / BILLION;
        total_query_time += query_time;

        if (query_time > 0.1f) {
            lprintf(LOG_WARNING, "It took %lfs to query: '%s', sort: %d (asc: %d), page: %d\n",
                    query_time,
                    query->query,
                    query->params.sort,
                    query->params.sort_asc,
                    query->params.page_number);
        }

        mse_async_query_decref(query);
        c->fn_data = NULL;
    } else if ((event == MG_EV_CLOSE || event == MG_EV_ERROR) && c->is_accepted && c->fn_data != NULL) {
        mse_async_query_t *query = (mse_async_query_t *) c->fn_data;
        mse_async_query_decref(query);
        if (event == MG_EV_ERROR) {
            internal_error_requests++;
        }
    }
}

void mse_serve(mse_t *mse_in)
{
    struct mg_mgr mgr;
    struct mg_connection *c;
    mse = mse_in;

    char *bind_addr = "http://0.0.0.0:4365";
    mg_mgr_init(&mgr);
    c = mg_http_listen(&mgr,
                       bind_addr,
                       &__mse_serve,
                       NULL);

    mg_log_set(MG_LL_ERROR);

    if (c == NULL) {
        lprintf(LOG_ERROR, "Unable to init mongoose.\n");
        return;
    }

    lprintf(LOG_INFO, "Listening on %s, mongoose version %s\n", bind_addr, MG_VERSION);
    while(1) mg_mgr_poll(&mgr, 1);
    mg_mgr_free(&mgr);
}
