#include "./query_parser.h"
#include "../testing_h/testing.h"

int __mse_handle_set_generator(mse_parser_status_t *ret, int negate)
{
    mse_set_generator_t tmp;
    ASSERT(ret->set_generator_node == NULL);
    ASSERT(mse_init_set_generator(&tmp,
                                  ret->parser_gen_type,
                                  ret->parser_op_type,
                                  ret->argument_buffer,
                                  strlen(ret->argument_buffer)));
    tmp.negate = negate;
    ASSERT(ret->set_generator_node = mse_init_interp_node_generator(tmp));
    return 1;
}

/// Calls the handler for a set generator then cleans the internal state
int mse_handle_set_generator(int negate, mse_parser_status_t *ret)
{
    ASSERT(ret->argument_buffer != NULL);
    int r = __mse_handle_set_generator(ret, negate);

    free(ret->argument_buffer);
    ret->argument_buffer = NULL;
    return r;
}

#define MSE_INSERT_END_EARLY 2

/*
/// Smelly dead code, I will leave this here just incase something needs debugging
static void print_tree(mse_interp_node_t *node, int h) {
    if (node == NULL) {
        return;
    }

    for (int i = 0; i < h; i++) {
        putchar('\t');
    }
    putchar('>');

    switch (node->type) {
    case MSE_INTERP_NODE_SET_GENERATOR:
        printf("generator | arg %s | op %d | operator %d",
               node->generator.argument,
               node->generator.generator_op,
               node->generator.generator_type);
        break;
    case MSE_INTERP_NODE_SET_CONSUMER:
        printf("consumer | probably negate");
        break;
    case MSE_INTERP_NODE_SET_OPERATOR:
        printf("operator | ");
        switch (node->op_type) {
        case MSE_SET_INTERSECTION:
            printf("AND");
            break;
        case MSE_SET_UNION:
            printf("OR");
            break;
        }
        break;
    }
    puts("");
    print_tree(node->l, h+1);
    print_tree(node->r, h+1);
}
*/

/// if the parent is a generator, then the parent should
/// become a child of node and, node should become the parent.
int __mse_insert_swap_parent(mse_parser_status_t *state,  mse_interp_node_t *node)
{
    if (node->type == MSE_INTERP_NODE_SET_OPERATOR) {
        // The parent should be swapped with the operator
        mse_interp_node_t tmp = *state->node;
        *state->node = *node;

        *node = tmp;
        state->node->l = node;
        return MSE_INSERT_END_EARLY;
    }
    return 1;
}

/// Handles the special cases
int __mse_insert_node_special(mse_parser_status_t *state, mse_interp_node_t *node)
{
    if (state->node == NULL) {
        return 1;
    }

    if (state->node->type == MSE_INTERP_NODE_SET_GENERATOR) {
        return __mse_insert_swap_parent(state, node);
    } else if (state->node->type == MSE_INTERP_NODE_SET_CONSUMER
               && state->node->l != NULL) {
        // if the parent is a consumer node then there should only be one child
        // for it, so if left is set then left should become the parent
        state->node = state->node->l;
        return __mse_insert_swap_parent(state, node);
    }
    return 1;
}

int __mse_insert_node(mse_parser_status_t *state, mse_interp_node_t *node)
{
    ASSERT(node != NULL);
    if (state->root == NULL) {
        state->root = state->node = node;
        return 1;
    }

    int r = __mse_insert_node_special(state, node);
    if (r == MSE_INSERT_END_EARLY) {
        return 1;
    }
    ASSERT(r);

    if (state->node->l == NULL) {
        state->node->l = node;
    } else if (state->node->r == NULL) {
        state->node = state->node->r = node;
    } else {
        return __mse_insert_swap_parent(state, node);
    }
    return 1;
}

int __mse_negate(mse_parser_status_t *state)
{
    mse_set_consumer_t consumer;
    ASSERT(mse_init_set_consumer(&consumer,
                                 MSE_SET_CONSUMER_NEGATE,
                                 "",
                                 0));

    mse_interp_node_t *node = NULL;
    ASSERT(node = mse_init_interp_node_consumer(consumer));
    ASSERT(__mse_insert_node(state, node));
    return 1;
}

int __mse_parser_status_push(mse_parser_status_t *state)
{
    ASSERT(state->stack_roots = realloc(state->stack_roots,
                                        ++state->stack_roots_len
                                        * sizeof(state->node)));
    state->stack_roots[state->stack_roots_len - 1] = state->node;
    return 1;
}

int __mse_parser_status_pop(mse_parser_status_t *state)
{
    ASSERT(state->stack_roots_len > 0);
    mse_interp_node_t *tmp = state->stack_roots[state->stack_roots_len - 1];
    if (state->stack_roots_len - 1 == 0) {
        free(state->stack_roots);
        state->stack_roots = NULL;
        state->stack_roots_len = 0;
    } else {
        ASSERT(state->stack_roots = realloc(state->stack_roots,
                                            --state->stack_roots_len));
    }

    if (tmp == NULL) {
        tmp = state->root;
    }
    state->node = tmp;
    return 1;
}

void __mse_free_parser_status(mse_parser_status_t *status)
{
    if (status->tmp_buffer != NULL) {
        free(status->tmp_buffer);
    }
    if (status->argument_buffer != NULL) {
        free(status->argument_buffer);
    }

    if (status->stack_roots != NULL) {
        lprintf(LOG_WARNING, "Unused %lu nodes on the stack\n", status->stack_roots_len);
        free(status->stack_roots);
    }

    if (status->set_generator_node != NULL) {
        lprintf(LOG_WARNING, "Unused interpretor node\n");
        mse_free_interp_node(status->set_generator_node);
    }
}
