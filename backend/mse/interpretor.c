#include "./interpretor.h"
#include "../testing_h/testing.h"
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>

/// Data for the worker threads
typedef struct mse_interp_node_thread_data_t {
    // Threading stuffs
    /// The semaphore of the parent
    sem_t *sem;
    /// Whether or not there was an error
    int *err;

    // Call parameters
    /// The node to operate on
    mse_interp_node_t *node;
    /// The place to return data to
    mse_search_intermediate_t *ret;
    /// Whether or not it is a dry run
    int dry_run;
    /// The cards index reference
    mse_all_printings_cards_t *cards;
} mse_interp_node_thread_data_t;

static void __mse_resolve_interp_tree_worker(void *__data, mse_thread_pool_t *pool)
{
    mse_interp_node_thread_data_t *data = (mse_interp_node_thread_data_t *) __data;
    int r = mse_resolve_interp_tree(data->node, data->ret, pool, data->dry_run, data->cards);
    if (!r) {
        lprintf(LOG_ERROR, "Cannot resolve node\n");
        *data->err = 1;
    }

    sem_post(data->sem);
    free(data);
}

static int __mse_queue_interp_tree_worker(sem_t *sem,
        int *err,
        mse_interp_node_t *node,
        mse_search_intermediate_t *ret,
        int dry_run,
        mse_all_printings_cards_t *cards,
        mse_thread_pool_t *pool)
{
    mse_interp_node_thread_data_t *data = malloc(sizeof(*data));
    ASSERT(data != NULL);

    memset(data, 0, sizeof(*data));
    data->sem = sem;
    data->err = err;
    data->node = node;
    data->ret = ret;
    data->dry_run = dry_run;
    data->cards = cards;

    mse_task_t task = {(void *) data, &__mse_resolve_interp_tree_worker};
    if (!mse_task_queue_greedy_enqueue(&pool->queue, task)) {
        lprintf(LOG_ERROR, "Cannot enqueue resolve task\n");
        free(data);
        return 0;
    }
    return 1;
}

static mse_interp_node_t *__mse_init_interp_node()
{
    mse_interp_node_t *ret = malloc(sizeof(*ret));
    ASSERT(ret != NULL);
    memset(ret, 0, sizeof(*ret));
    return ret;
}

mse_interp_node_t *mse_init_interp_node_operation(mse_set_operator_type_t operation)
{
    mse_interp_node_t *ret = __mse_init_interp_node();
    ASSERT(ret != NULL);

    ret->type = MSE_INTERP_NODE_SET_OPERATOR;
    ret->op_type = operation;
    return ret;
}

mse_interp_node_t *mse_init_interp_node_generator(mse_set_generator_t generator)
{
    mse_interp_node_t *ret = __mse_init_interp_node();
    ASSERT(ret != NULL);

    ret->type = MSE_INTERP_NODE_SET_GENERATOR;
    ret->generator = generator;
    return ret;
}

mse_interp_node_t *mse_init_interp_node_consumer(mse_set_consumer_t consumer)
{
    mse_interp_node_t *ret = __mse_init_interp_node();
    ASSERT(ret != NULL);

    ret->type = MSE_INTERP_NODE_SET_CONSUMER;
    ret->consumer = consumer;
    return ret;
}

void mse_free_interp_node(mse_interp_node_t *node)
{
    if (node == NULL) {
        return;
    }

    switch(node->type) {
    case MSE_INTERP_NODE_SET_OPERATOR:
        break;
    case MSE_INTERP_NODE_SET_GENERATOR:
        mse_free_set_generator(&node->generator);
        break;
    case MSE_INTERP_NODE_SET_CONSUMER:
        mse_free_set_consumer(&node->consumer);
        break;
    }

    mse_free_interp_node(node->l);
    mse_free_interp_node(node->r);
    free(node);
}

static int __mse_resolve_interp_leaf_generator(mse_interp_node_t *node,
        mse_search_intermediate_t *ret,
        mse_thread_pool_t *pool,
        int dry_run,
        mse_all_printings_cards_t *cards)
{
    ASSERT(node->l == NULL);
    ASSERT(node->r == NULL);
    if (dry_run) {
        return 1;
    }

    ASSERT(mse_generate_set(&node->generator,
                            ret,
                            cards,
                            pool));
    return 1;
}

static int __mse_resolve_interp_tree_consumer(mse_interp_node_t *node,
        mse_search_intermediate_t *ret,
        mse_thread_pool_t *pool,
        int dry_run,
        mse_all_printings_cards_t *cards)
{
    // Assert that there is only one child and that it is the left one.
    // XOR to make sure only one is null
    ASSERT((node->l == NULL) ^ (node->r == NULL));
    if (node->l == NULL) {
        node->l = node->r;
    }

    // node->l is now the only none-null node
    if (dry_run) {
        return 1;
    }

    // Generate the children
    mse_search_intermediate_t child_ret;
    ASSERT(mse_resolve_interp_tree(node->l, &child_ret, pool, dry_run, cards));

    // Consume the children
    int r = mse_consume_set(&node->consumer,
                            ret,
                            cards,
                            &child_ret,
                            pool);

    mse_free_search_intermediate(&child_ret);
    ASSERT(r);
    return 1;
}

static int __mse_resolve_interp_tree_operator(mse_interp_node_t *node,
        mse_search_intermediate_t *ret,
        mse_thread_pool_t *pool,
        int dry_run,
        mse_all_printings_cards_t *cards)
{
    // Validate the node
    ASSERT(node->l != NULL);
    ASSERT(node->r != NULL);

    // Calculate sets a and b (this is the recursive step)
    mse_search_intermediate_t a;
    memset(&a, 0, sizeof(a));

    int err = mse_resolve_interp_tree(node->l, &a, pool, dry_run, cards);

    mse_search_intermediate_t b;
    memset(&b, 0, sizeof(b));
    err = mse_resolve_interp_tree(node->r, &b, pool, dry_run, cards);

    if (dry_run || err) {
        mse_free_search_intermediate(&a);
        mse_free_search_intermediate(&b);
        if (dry_run) {
            return 1;
        } else {
            lprintf(LOG_ERROR, "An error occurred\n");
            return 0;
        }
    }

    // Perform set operation
    int r = 0;
    memset(ret, 0, sizeof(*ret));
    switch(node->op_type) {
    case MSE_SET_UNION:
        r = mse_set_union(ret, &a, &b);
        break;
    case MSE_SET_INTERSECTION:
        r = mse_set_intersection(ret, &a, &b);
        break;
    }

    // Cleanup
    mse_free_search_intermediate(&a);
    mse_free_search_intermediate(&b);
    ASSERT(r);
    return 1;
}

int mse_resolve_interp_tree(mse_interp_node_t *root,
                            mse_search_intermediate_t *ret,
                            mse_thread_pool_t *pool,
                            int dry_run,
                            mse_all_printings_cards_t *cards)
{
    ASSERT(root != NULL);
    switch(root->type) {
    case MSE_INTERP_NODE_SET_GENERATOR:
        ASSERT(__mse_resolve_interp_leaf_generator(root, ret, pool, dry_run, cards));
        break;
    case MSE_INTERP_NODE_SET_OPERATOR:
        ASSERT(__mse_resolve_interp_tree_operator(root, ret, pool, dry_run, cards));
        break;
    case MSE_INTERP_NODE_SET_CONSUMER:
        ASSERT(__mse_resolve_interp_tree_consumer(root, ret, pool, dry_run, cards));
        break;
    default:
        lprintf(LOG_ERROR, "Undefined node type\n");
        return 0;
    }
    return 1;
}
