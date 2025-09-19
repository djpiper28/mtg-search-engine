#include "./test_re2.h"
#include "../testing_h/testing.h"
#include "../mse/re2_wrapper.h"

static int test_good_case()
{
    mse_re_t re;
    ASSERT(mse_re_init(&re, "ma?s{2}ive\\scar."));
    ASSERT(mse_re_matches(&re, "massive cars"));
    ASSERT(!mse_re_matches(&re, "random text"));
    mse_re_free(&re);
    return 1;
}

static int test_bad_case()
{
    mse_re_t re;
    ASSERT(!mse_re_init(&re, "(ashdaskjdhasjkd"));
    mse_re_free(&re);
    return 1;
}

SUB_TEST(test_re2, {&test_good_case, "Test re2 good case"},
{&test_bad_case, "Test re2 bad case"})
