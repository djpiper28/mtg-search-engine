#include "./generators.h"
#include "./generator_float_fields.h"
#include "./generator_set.h"
#include "./generator_oracle.h"
#include "./generator_name.h"
#include "./generator_colour.h"
#include "../testing_h/testing.h"
#include "generator_type.h"
#include "mse_formats.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

int mse_init_set_generator(mse_set_generator_t *ret,
                           mse_set_generator_type_t gen_type,
                           mse_set_generator_operator_t op_type,
                           char *argument,
                           size_t len)
{
    ASSERT(__mse_validate_generator_op_combo(gen_type, op_type));
    memset(ret, 0, sizeof(*ret));
    ret->generator_type = gen_type;
    ret->generator_op = op_type;

    size_t buf_len = sizeof(*ret->argument) * (len + 1);
    ret->argument = malloc(buf_len);
    ASSERT(ret->argument != NULL);

    strcpy(ret->argument, argument);
    ret->argument[len] = 0;
    return 1;
}

void mse_free_set_generator(mse_set_generator_t *gen)
{
    if (gen->argument != NULL) {
        free(gen->argument);
    }
    memset(gen, 0, sizeof(*gen));
}

static int __mse_is_op_set_includes(mse_set_generator_operator_t op_type)
{
    if (op_type == MSE_SET_GENERATOR_OP_EQUALS) {
        return 1;
    }

    if (op_type == MSE_SET_GENERATOR_OP_INCLUDES) {
        return 1;
    }
    return 0;
}

int __mse_validate_generator_op_combo(mse_set_generator_type_t gen_type,
                                      mse_set_generator_operator_t op_type)
{
    switch(gen_type) {
    case MSE_SET_GENERATOR_COLOUR:
    case MSE_SET_GENERATOR_CMC:
    case MSE_SET_GENERATOR_LOYALTY:
    case MSE_SET_GENERATOR_COLOUR_IDENTITY:
    case MSE_SET_GENERATOR_POWER:
    case MSE_SET_GENERATOR_TOUGHNESS:
        return 1;
    case MSE_SET_GENERATOR_NAME:
    case MSE_SET_GENERATOR_ORACLE_TEXT:
    case MSE_SET_GENERATOR_SET:
    case MSE_SET_GENERATOR_TYPE:
    case MSE_SET_GENERATOR_BANNED:
    case MSE_SET_GENERATOR_LEGAL:
    case MSE_SET_GENERATOR_RESTRICTED:
    case MSE_SET_GENERATOR_UNPLAYABLE:
        return __mse_is_op_set_includes(op_type);
    }
    return 0;
}

int mse_generate_set(mse_set_generator_t *gen,
                     mse_search_intermediate_t *res,
                     mse_all_printings_cards_t *cards)
{
    memset(res, 0, sizeof(*res));
    switch(gen->generator_type) {
    case MSE_SET_GENERATOR_COLOUR:
        return mse_generate_set_colours(gen, res, cards);
    case MSE_SET_GENERATOR_COLOUR_IDENTITY:
        return mse_generate_set_colour_identity(gen, res, cards);
    case MSE_SET_GENERATOR_NAME:
        return mse_generate_set_name(gen, res, cards);
    case MSE_SET_GENERATOR_ORACLE_TEXT:
        return mse_generate_set_oracle(gen, res, cards);
    case MSE_SET_GENERATOR_SET:
        return mse_generate_set_set(gen, res, cards);
    case MSE_SET_GENERATOR_POWER:
        return mse_generate_set_power(gen, res, cards);
    case MSE_SET_GENERATOR_TOUGHNESS:
        return mse_generate_set_toughness(gen, res, cards);
    case MSE_SET_GENERATOR_CMC:
        return mse_generate_set_cmc(gen, res, cards);
    case MSE_SET_GENERATOR_LOYALTY:
        return mse_generate_set_loyalty(gen, res, cards);
    case MSE_SET_GENERATOR_TYPE:
        return mse_generate_set_type(gen, res, cards);
    case MSE_SET_GENERATOR_BANNED:
        return mse_generate_banned(gen, res, cards);
    case MSE_SET_GENERATOR_LEGAL:
        return mse_generate_legal(gen, res, cards);
    case MSE_SET_GENERATOR_RESTRICTED:
        return mse_generate_restricted(gen, res, cards);
    case MSE_SET_GENERATOR_UNPLAYABLE:
        return mse_generate_unplayable(gen, res, cards);
    }
    return 1;
}

static int __mse_gen_type_1_char(char c, mse_set_generator_type_t *ret)
{
    switch (tolower(c)) {
    case 'c':
        *ret = MSE_SET_GENERATOR_COLOUR;
        break;
    case 'i':
        *ret = MSE_SET_GENERATOR_COLOUR_IDENTITY;
        break;
    case 'p':
        *ret = MSE_SET_GENERATOR_POWER;
        break;
    case 't':
        *ret = MSE_SET_GENERATOR_TOUGHNESS;
        break;
    case 'n':
        *ret = MSE_SET_GENERATOR_NAME;
        break;
    case 'o':
        *ret = MSE_SET_GENERATOR_ORACLE_TEXT;
        break;
    case 's':
        *ret = MSE_SET_GENERATOR_SET;
        break;
    case 'l':
        *ret = MSE_SET_GENERATOR_LOYALTY;
        break;
    default:
        return 0;
    }
    return 1;
}

#define __MSE_GEN_TYPE_CMP(s, type) \
if (strcmp(tmp, s) == 0) *ret = type, found = 1

int mse_gen_type(char *str, mse_set_generator_type_t *ret)
{
    size_t len = strlen(str);
    if (len == 1) {
        return __mse_gen_type_1_char(str[0], ret);
    }

    char *tmp = strdup(str);
    ASSERT(tmp != NULL);
    for (size_t i = 0; i < len; i++) {
        tmp[i] = tolower(tmp[i]);
    }

    int found = 0;
    // Sorry code highlighter
    __MSE_GEN_TYPE_CMP("identity", MSE_SET_GENERATOR_COLOUR_IDENTITY);
    else __MSE_GEN_TYPE_CMP("commander", MSE_SET_GENERATOR_COLOUR_IDENTITY);
    else __MSE_GEN_TYPE_CMP("color", MSE_SET_GENERATOR_COLOUR);
    else __MSE_GEN_TYPE_CMP("colour", MSE_SET_GENERATOR_COLOUR);
    else __MSE_GEN_TYPE_CMP("power", MSE_SET_GENERATOR_POWER);
    else __MSE_GEN_TYPE_CMP("toughness", MSE_SET_GENERATOR_TOUGHNESS);
    else __MSE_GEN_TYPE_CMP("set", MSE_SET_GENERATOR_SET);
    else __MSE_GEN_TYPE_CMP("cmc", MSE_SET_GENERATOR_CMC);
    else __MSE_GEN_TYPE_CMP("loyalty", MSE_SET_GENERATOR_LOYALTY);
    else __MSE_GEN_TYPE_CMP("manacost", MSE_SET_GENERATOR_CMC);
    else __MSE_GEN_TYPE_CMP("name", MSE_SET_GENERATOR_NAME);
    else __MSE_GEN_TYPE_CMP("oracle", MSE_SET_GENERATOR_ORACLE_TEXT);
    else __MSE_GEN_TYPE_CMP("type", MSE_SET_GENERATOR_TYPE);
    else __MSE_GEN_TYPE_CMP("types", MSE_SET_GENERATOR_TYPE);
    else __MSE_GEN_TYPE_CMP("banned", MSE_SET_GENERATOR_BANNED);
    else __MSE_GEN_TYPE_CMP("legal", MSE_SET_GENERATOR_LEGAL);
    else __MSE_GEN_TYPE_CMP("restricted", MSE_SET_GENERATOR_RESTRICTED);
    else __MSE_GEN_TYPE_CMP("unplayable", MSE_SET_GENERATOR_UNPLAYABLE);

    if (!found) {
        lprintf(LOG_ERROR, "'%s' in not a valid op_name\n", tmp);
    }

    free(tmp);
    return found;
}
