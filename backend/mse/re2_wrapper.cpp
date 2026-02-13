#include "./re2_wrapper.h"
#include "../testing_h/testing.h"
#include <string>
#include <string.h>

int mse_re_init(mse_re_t *re, char *str)
{
    memset(re, 0, sizeof(*re));

    std::string restr = std::string(str);
    RE2::Options options;
    options.set_case_sensitive(false);
    options.set_dot_nl(true);

    re->__re = new RE2(restr, options);
    if (!re->__re->ok()) {
        lprintf(LOG_ERROR, "Invalid regex, cannot compile\n");
        mse_re_free(re);
        return 0;
    }
    return 1;
}

int mse_re_matches(mse_re_t *re, char *str)
{
    return RE2::FullMatch(std::string(str), *re->__re) ? 1 : 0;
}

void mse_re_free(mse_re_t *re)
{
    if (re->__re != NULL) {
        delete re->__re;
    }
    memset(re, 0, sizeof(*re));
}
