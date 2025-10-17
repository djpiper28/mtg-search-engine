#include "./avl_tree.h"
#include "../testing_h/testing.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX(a, b) (a > b ? a : b)

static inline size_t __tree_height(mse_avl_tree_node_t * restrict node)
{
    if (node == NULL) {
        return 0;
    }
    return node->height;
}

void mse_free_tree(mse_avl_tree_node_t * restrict tree)
{
    if (tree == NULL) {
        return;
    }
    mse_free_tree(tree->l);
    mse_free_tree(tree->r);

    if (tree->free_payload != NULL) {
        tree->free_payload(tree->payload);
    }
    free(tree);
}

int mse_tree_balance(mse_avl_tree_node_t * restrict node)
{
    if (node == NULL) {
        return 0;
    }

    int lh = __tree_height(node->l);
    int rh = __tree_height(node->r);

    return lh - rh;
}

mse_avl_tree_node_t *mse_init_avl_tree_node(void (*free_payload)(void *payload),
        int (*cmp_payload)(void *a, void *b),
        void *payload)
{
    mse_avl_tree_node_t *tree = malloc(sizeof * tree);
    ASSERT(tree != NULL);

    tree->payload = payload;
    tree->cmp_payload = cmp_payload;
    tree->free_payload = free_payload;
    tree->height = 1;
    tree->l = tree->r = NULL;
    return tree;
}

static void __print_tree(mse_avl_tree_node_t * restrict tree, int h)
{
    for (int i = 0; i < h; i++) {
        printf("  |");
    }
    printf("  |> %p %lu\n", tree->payload, tree->height);

    if (tree->l)  {
        __print_tree(tree->l, h + 1);
    } else {
        puts("--");
    }

    if (tree->r) {
        __print_tree(tree->r, h + 1);
    } else {
        puts("--");
    }
}

void mse_print_tree(mse_avl_tree_node_t * restrict root)
{
    __print_tree(root, 0);
}

static inline void __rotate_update_heights(mse_avl_tree_node_t * restrict root)
{
    if (root->r != NULL) {
        root->r->height = MAX(__tree_height(root->r->l),
                              __tree_height(root->r->r)) + 1;
    }

    if (root->l != NULL) {
        root->l->height = MAX(__tree_height(root->l->l),
                              __tree_height(root->l->r)) + 1;
    }
    root->height = MAX(__tree_height(root->l),
                       __tree_height(root->r)) + 1;
}

static inline mse_avl_tree_node_t *__rotate_r(mse_avl_tree_node_t * restrict y)
{
    /* Rotation (right):
    *      x          y
    *    y   c  ->  a   x
    *  a   b          b   c
    **/
    mse_avl_tree_node_t *x = y->l;
    mse_avl_tree_node_t *t2 = x->r;

    // Perform rotation
    x->r = y;
    y->l = t2;

    __rotate_update_heights(x);
    return x;
}

static inline mse_avl_tree_node_t *__rotate_l(mse_avl_tree_node_t * restrict x)
{
    /* Rotation (left):
    *    x              y
    *  a   y    ->    a   x
    *    b   c      b   c
    **/
    mse_avl_tree_node_t *y = x->r;
    mse_avl_tree_node_t *t2 = y->l;

    // Perform rotation
    y->l = x;
    x->r = t2;

    __rotate_update_heights(y);
    return y;
}

static inline int __cmp_payload(mse_avl_tree_node_t * restrict a, mse_avl_tree_node_t * restrict b)
{
    if (a == NULL || b == NULL) {
        return 0;
    } else {
        return a->cmp_payload(a->payload, b->payload);
    }
}

static inline mse_avl_tree_node_t *__do_insert_node(mse_avl_tree_node_t * restrict root, mse_avl_tree_node_t * restrict node)
{
    // Base case
    if (root == NULL) {
        return node;
    }

    // BST insert
    int cmp = __cmp_payload(node, root);

    // cmp != 0 as mse_insert_node checks this
    if (cmp <= 0) {
        // Add left
        root->l = __do_insert_node(root->l, node);
    } else {
        // Add right
        root->r = __do_insert_node(root->r, node);
    }

    // Set height
    root->height = MAX(__tree_height(root->l),
                       __tree_height(root->r)) + 1;

    // Balance trees
    int balance = mse_tree_balance(root);
    int cmp_left = __cmp_payload(node, root->l);
    int cmp_right = __cmp_payload(node, root->r);

    if (balance > 1 && cmp_left < 0) {
        return __rotate_r(root);
    } else if (balance < -1 && cmp_right > 0) {
        return __rotate_l(root);
    } else if (balance > 1 && cmp_left > 0) {
        root->l = __rotate_l(root->l);
        return __rotate_r(root);
    } else if (balance < -1 && cmp_right < 0) {
        root->r = __rotate_r(root->r);
        return __rotate_l(root);
    }

    return root;
}

int mse_insert_node(mse_avl_tree_node_t ** restrict root, mse_avl_tree_node_t * restrict node)
{
    if (*root == NULL) {
        *root = node;
        return 1;
    }

    if (mse_find_payload(*root, node->payload)) {
        return 0;
    }
    *root = __do_insert_node(*root, node);
    return 1;
}

mse_avl_tree_node_t *mse_find_payload(mse_avl_tree_node_t * restrict node, void * restrict payload)
{
    if (node == NULL) {
        return NULL;
    }

    int cmp = node->cmp_payload(payload, node->payload);
    if (cmp == 0) {
        return node;
    } else if (cmp < 0) {
        return mse_find_payload(node->l, payload);
    } else {
        return mse_find_payload(node->r, payload);
    }
}

size_t mse_tree_size(mse_avl_tree_node_t * restrict node)
{
    if (node == NULL) {
        return 0;
    }

    return 1 + mse_tree_size(node->l) + mse_tree_size(node->r);
}

mse_avl_tree_node_t *mse_shallow_copy_tree_node(mse_avl_tree_node_t * restrict node)
{
    if (node == NULL) {
        return NULL;
    }

    return mse_init_avl_tree_node(node->free_payload, node->cmp_payload, node->payload);
}

static inline int __add_node_to_lookup(mse_avl_tree_node_t ** restrict res, mse_avl_tree_node_t * restrict __node)
{
    mse_avl_tree_node_t *node = mse_shallow_copy_tree_node(__node);
    ASSERT(node != NULL);
    node->free_payload = NULL; // The memory is owned by the tree that generated the lookup
    ASSERT(mse_insert_node(res, node));
    return 1;
}

static inline int __tree_lookup(mse_avl_tree_node_t * restrict node, mse_avl_tree_node_t ** restrict res, int less_than, void * restrict cmp_payload)
{
    if (node == NULL) {
        return 1;
    }

    int cmp = node->cmp_payload(node->payload, cmp_payload);
    if (less_than) {
        if (cmp < 0) {
            ASSERT(__add_node_to_lookup(res, node));
            ASSERT(__tree_lookup(node->r, res, less_than, cmp_payload));
        }
        ASSERT(__tree_lookup(node->l, res, less_than, cmp_payload));
    } else {
        if (cmp > 0) {
            ASSERT(__add_node_to_lookup(res, node));
            ASSERT(__tree_lookup(node->l, res, less_than, cmp_payload));
        }
        ASSERT(__tree_lookup(node->r, res, less_than, cmp_payload));
    }
    return 1;
}

int mse_tree_lookup(mse_avl_tree_node_t * restrict root, mse_avl_tree_node_t ** restrict res, int less_than, void * restrict cmp_payload)
{
    *res = NULL;
    return __tree_lookup(root, res, less_than, cmp_payload);
}

static inline int __tree_lookup_2(mse_avl_tree_node_t * restrict node, mse_avl_tree_node_t ** restrict res, void * restrict lower, void * restrict upper)
{
    if (node == NULL) {
        return 1;
    }

    int cmp_l = node->cmp_payload(node->payload, lower);
    int cmp_u = node->cmp_payload(node->payload, upper);

    if (cmp_l > 0 && cmp_u < 0) {
        ASSERT(__add_node_to_lookup(res, node));
    }

    if (cmp_l >= 0) {
        ASSERT(__tree_lookup_2(node->l, res, lower, upper));
    }

    if (cmp_u <= 0) {
        ASSERT(__tree_lookup_2(node->r, res, lower, upper));
    }

    return 1;
}

int mse_tree_lookup_2(mse_avl_tree_node_t * restrict root, mse_avl_tree_node_t ** restrict res, void * restrict lower, void * restrict upper)
{
    *res = NULL;
    if (root != NULL) {
        ASSERT(root->cmp_payload(lower, upper) < 0);
    }
    return __tree_lookup_2(root, res, lower, upper);
}
