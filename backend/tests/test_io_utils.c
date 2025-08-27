#include "./test_io_utils.h"
#include "../testing_h/testing.h"
#include "../mse/io_utils.h"
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <time.h>

// Hack for the local scope
typedef struct tm tm;

#define TEST_BASIC_READ_WRITE(type, value) \
static int test_##type##_read_write() \
{ \
    type val_1 = value; \
    int fid[2]; \
    ASSERT(pipe(fid) == 0); \
    FILE *r = fdopen(fid[0], "rb"); \
    ASSERT(r != NULL); \
    FILE *w = fdopen(fid[1], "wb"); \
    ASSERT(w != NULL); \
    ASSERT(mse_write_##type(w, val_1)); \
    fclose(w); \
    type val_2; \
    ASSERT(mse_read_##type(r, &val_2)); \
    ASSERT(memcmp(&val_1, &val_2, sizeof(val_1)) == 0); \
    fclose(r); \
    return 1; \
}

time_t time_local;

TEST_BASIC_READ_WRITE(float, M_PI)
TEST_BASIC_READ_WRITE(int, INT_MAX)
TEST_BASIC_READ_WRITE(size_t, LLONG_MAX)
TEST_BASIC_READ_WRITE(tm, *gmtime(&time_local))

#define STR_MESSAGE "Lorem ipsum dolor sit amet, officia excepteur ex fugiat reprehenderit enim labore culpa sint ad nisi Lorem pariatur mollit ex esse exercitation amet. Nisi anim cupidatat excepteur officia. Reprehenderit nostrud nostrud ipsum Lorem est aliquip amet voluptate voluptate dolor minim nulla est proident. Nostrud officia pariatur ut officia. Sit irure elit esse ea nulla sunt ex occaecat reprehenderit commodo officia dolor Lorem duis laboris cupidatat officia voluptate. Culpa proident adipisicing id nulla nisi laboris ex in Lorem sunt duis officia eiusmod. Aliqua reprehenderit commodo ex non excepteur duis sunt velit enim. Voluptate laboris sint cupidatat ullamco ut ea consectetur et est culpa et culpa duis."

static int test_str_read_write()
{
    char * val_1 = STR_MESSAGE;

    int fid[2];
    ASSERT(pipe(fid) == 0);

    FILE *r = fdopen(fid[0], "rb");
    ASSERT(r != NULL);

    FILE *w = fdopen(fid[1], "wb");
    ASSERT(w != NULL);

    ASSERT(mse_write_str(w, val_1));
    fclose(w);

    char *val_2;
    ASSERT(mse_read_str(r, &val_2));

    ASSERT(val_2 != NULL);
    ASSERT(strcmp(val_1, val_2) == 0);
    fclose(r);
    free(val_2);
    return 1;
}

static int test_str_read_write_null()
{
    int fid[2];
    ASSERT(pipe(fid) == 0);

    FILE *r = fdopen(fid[0], "rb");
    ASSERT(r != NULL);

    FILE *w = fdopen(fid[1], "wb");
    ASSERT(w != NULL);

    ASSERT(mse_write_str(w, NULL));
    fclose(w);

    char *val_2;
    ASSERT(mse_read_str(r, &val_2));

    ASSERT(val_2 == NULL);
    fclose(r);
    free(val_2);
    return 1;
}

static int test_mse_to_float()
{
    float ret = 0;
    ASSERT(mse_to_float("5", &ret));
    ASSERT(fabs(ret - 5) < 0.001);

    ASSERT(mse_to_float("5.2", &ret));
    ASSERT(fabs(ret - 5.2) < 0.001);

    ASSERT(!mse_to_float("pee pee poo poo", &ret));
    return 1;
}

static int test_mse_to_lower()
{
    char *cpy = NULL;
    ASSERT(cpy = mse_to_lower("HaStE"));
    ASSERT(strcmp("haste", cpy) == 0);
    free(cpy);
    return 1;
}

SUB_TEST(test_io_utils, {&test_float_read_write, "Test float read and, write"},
{&test_int_read_write, "Test int read and, write"},
{&test_size_t_read_write, "Test size_t read and, write"},
{&test_tm_read_write, "Test struct tm read and, write"},
{&test_str_read_write, "Test string read and, write"},
{&test_str_read_write_null, "Test string read and, write (null)"},
{&test_mse_to_float, "Test strtod wrapper"},
{&test_mse_to_lower, "Test mse_to_lower"})
