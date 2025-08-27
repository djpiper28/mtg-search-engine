#include "./test_uuid.h"
#include "../testing_h/testing.h"
#include "../mse/uuid.h"
#include <unistd.h>
#include <string.h>

static int test_uuid_read_write()
{
    mse_uuid_t uuid;
    for (size_t i = 0; i < sizeof(uuid); i++) {
        uuid.bytes[i] = (char) i;
    }

    int fid[2];
    ASSERT(pipe(fid) == 0);

    FILE *r = fdopen(fid[0], "rb");
    ASSERT(r != NULL);

    FILE *w = fdopen(fid[1], "wb");
    ASSERT(w != NULL);

    ASSERT(mse_write_uuid(w, uuid));
    fclose(w);

    mse_uuid_t uuid_2;
    ASSERT(mse_read_uuid(r, &uuid_2));
    ASSERT(memcmp(&uuid, &uuid_2, sizeof(uuid)) == 0);
    fclose(r);

    return 1;
}

#define UUID_1_STR "7cfbdb70-96dd-49ac-8f7a-4658996b2c2b"
#define UUID_2_STR "7CFBDB70-96DD-49AC-8F7A-4658996B2C2B"
static int test_uuid_from_string()
{
    int status = 0;
    mse_uuid_t uuid_1 = mse_from_string(UUID_1_STR, &status);
    ASSERT(status == 1);

    mse_uuid_t uuid_2 = mse_from_string(UUID_2_STR, &status);
    ASSERT(status == 1);

    // Test that they are read the same
    ASSERT(memcmp(&uuid_1, &uuid_2, sizeof(uuid_1)) == 0);

    // Test that they are read as the input is
    mse_uuid_t uuid_val = {
        {
            0x7c, 0xfb, 0xdb, 0x70, 0x96, 0xdd, 0x49, 0xac, 0x8f, 0x7a, 0x46, 0x58, 0x99, 0x6b, 0x2c, 0x2b
        }
    };
    lprintf(LOG_INFO, "%p %p\n", *(long *)&uuid_1.bytes[0], *(long *)&uuid_1.bytes[8]);
    lprintf(LOG_INFO, "%p %p\n", *(long *)&uuid_val.bytes[0], *(long *)&uuid_val.bytes[8]);
    ASSERT(memcmp(&uuid_1, &uuid_val, sizeof(uuid_1)) == 0);

    return 1;
}

static int test_uuid_from_string_invalid()
{
    int status = 0;
    mse_uuid_t uuid = mse_from_string("", &status);
    ASSERT(status == 0);

    uuid = mse_from_string("testing 132 123 123 123", &status);
    ASSERT(status == 0);

    uuid = mse_from_string("ef37a292-7f41-44db-820e-b3a6bf928902e43a36e0-89ff-43cb-8b35-960e37468623", &status);
    ASSERT(status == 0);

    uuid = mse_from_string("6306g3f2-183f-4120-b534-2b64f70c95e2", &status);
    ASSERT(status == 0);

    uuid = mse_from_string("c54a65ee-a6e5-4895-ba77-89cb5655fed", &status);
    ASSERT(status == 0);

    return 1;
}

static int test_set_code_read_write()
{
    mse_set_code_t set = {'M', '2', '0'};

    int fid[2];
    ASSERT(pipe(fid) == 0);

    FILE *r = fdopen(fid[0], "rb");
    ASSERT(r != NULL);

    FILE *w = fdopen(fid[1], "wb");
    ASSERT(w != NULL);

    ASSERT(mse_write_set_code(w, set));
    fclose(w);

    mse_set_code_t set_2;
    ASSERT(mse_read_set_code(r, &set_2));
    fclose(r);

    ASSERT(memcmp(set, set_2, sizeof(mse_set_code_t)) == 0);

    return 1;
}

static int test_uuid_cmp()
{
    mse_uuid_t a, b;
    memset(a.bytes, 0, sizeof(a.bytes));
    memset(b.bytes, 0, sizeof(b.bytes));

    ASSERT(mse_uuid_cmp(a, b) == 0);

    a.bytes[0] = 0xFF;
    ASSERT(mse_uuid_cmp(a, b) > 0);

    a.bytes[0] = 0;
    b.bytes[0] = 0xFF;
    ASSERT(mse_uuid_cmp(a, b) < 0);

    a = mse_min_uuid();
    b = mse_max_uuid();
    ASSERT(mse_uuid_cmp(a, b) < 0);

    return 1;
}

#define SET_SHORT "m20"
#define SET_LONG "uplist"

static int test_get_set_code()
{
    mse_set_code_t code;
    ASSERT(mse_get_set_code("", &code) == 0);
    ASSERT(mse_get_set_code(
               "Lorem ipsum dolor sit amet, qui minim labore adipisicing minim sint cillum sint consectetur cupidatat.",
               &code) == 0);

    ASSERT(mse_get_set_code(SET_SHORT, &code));
    ASSERT(strncmp((char *) code, SET_SHORT, sizeof(code)) == 0);

    ASSERT(mse_get_set_code(SET_LONG, &code));
    ASSERT(strncmp((char *) code, SET_LONG, sizeof(code)) == 0);

    ASSERT(mse_get_set_code("M20", &code));
    ASSERT(strncmp((char *) code, "m20", sizeof(code)) == 0);
    return 1;
}

static int test_max_uuid()
{
    mse_uuid_t m_uuid = mse_max_uuid();
    for (size_t i = 0; i < sizeof(m_uuid.bytes) / sizeof(*m_uuid.bytes); i++) {
        ASSERT(m_uuid.bytes[i] == 0xFF);
    }
    return 1;
}

static int test_min_uuid()
{
    mse_uuid_t m_uuid = mse_min_uuid();
    for (size_t i = 0; i < sizeof(m_uuid.bytes) / sizeof(*m_uuid.bytes); i++) {
        ASSERT(m_uuid.bytes[i] == 0);
    }
    return 1;
}

#define UUID_3_STR "f2d39b0a-7929-4789-a7ba-1c640f605a93"
static int test_uuid_str_round_trip()
{
    int status = 0;
    mse_uuid_t uuid = mse_from_string(UUID_3_STR, &status);
    ASSERT(status == 1);

    char *uuid_str = mse_uuid_as_string(uuid);
    ASSERT(uuid_str != NULL);
    ASSERT(strcmp(UUID_3_STR, uuid_str) == 0);
    free(uuid_str);
    return 1;
}

SUB_TEST(test_uuid, {&test_uuid_read_write, "UUID read and, write"},
{&test_uuid_from_string, "UUID from string"},
{&test_uuid_from_string_invalid, "UUID from string - invalid"},
{&test_set_code_read_write, "Set code read and, write"},
{&test_uuid_cmp, "Test UUID compare"},
{&test_get_set_code, "Test set code read function"},
{&test_max_uuid, "Test max UUID"},
{&test_min_uuid, "Test min UUID"},
{&test_uuid_str_round_trip, "Test UUID to string, and from string round trip"})
