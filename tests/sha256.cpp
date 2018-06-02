#include <gtest/gtest.h>
#include <cstdio>
#include <MyCryptoLib/sha256.hpp>

class SHA256Test : public testing::Test {
public:
    static FILE * ftestlong, * ftestshort;

    static void SetUpTestCase()
    {
        ftestshort = fopen("sha256data/SHA256ShortMsg.rsp", "r");
        ftestlong = fopen("sha256data/SHA256LongMsg.rsp", "r");
    }
    static void TearDownTestCase()
    {
        fclose(ftestshort);
        fclose(ftestlong);
    }
};

FILE * SHA256Test::ftestlong = NULL;
FILE * SHA256Test::ftestshort = NULL;

TEST_F(SHA256Test, Sha256Padding) {
    uint8_t ex[64] = {0};
    ex[0] = 'a'; ex[1] = 'b'; ex[2] = 'c';
    ex[3] = 0x80; ex[63] = 24;

    uint8_t tt[64];
    tt[0] = 'a'; tt[1] = 'b'; tt[2] = 'c';
    padding(tt, 3, 64, 3);

    for (int i = 0; i < 64; i++)
        if (ex[i] != tt[i]) FAIL();
    SUCCEED();
}

TEST_F(SHA256Test, Sha256PaddingZero) {
    uint8_t ex[64] = {0};
    ex[0] = 0x80; ex[63] = 0;

    uint8_t tt[64];
    padding(tt, 0, 64, 0);

    for (int i = 0; i < 64; i++)
        if (ex[i] != tt[i]) FAIL();
    SUCCEED();
}

static
void handle_test(
    ByteBlock & msg_block,
    ByteBlock & md_block,
    ByteBlock & result_block,
    FILE * f
) {
    SHA256 algorithm;

    unsigned length;
    fscanf(f, "Len = %d\n", &length);
    length >>= 2;

    char * msg = new char [length + 1];
    fscanf(f, "Msg = %s\n", msg);
    msg_block = hex_to_bytes(msg, length);
    delete [] msg;

    char md[32 * 2 + 1];
    fscanf(f, "MD = %s\n", md);
    md_block = hex_to_bytes(md, 32 * 2);

    algorithm.hash(msg_block, result_block);
}
static
void print_difference(ByteBlock const & exp, ByteBlock const & res, int n_test)
{
    fprintf(stderr, "\n");
    fprintf(stderr, "-=-=-=- test #%d -=-=-=-\n", n_test);
    fprintf(stderr, "Expected: %s\n", hex_representation(exp).c_str());
    fprintf(stderr, "Result:   %s\n", hex_representation(res).c_str());
    fprintf(stderr, "\n");
}

TEST_F(SHA256Test, SHA256ShortMsg) {
    int n_test = 1;
    while (!feof(ftestshort))
    {
        ByteBlock msg_block, md_block, result_block;
        try {
            handle_test(msg_block, md_block, result_block, ftestshort);
        } catch(...) {
            fprintf(stderr, "%s\n", "Something wrong here...");
        }
        if (!equal(md_block, result_block))
        {
            print_difference(md_block, result_block, n_test);
            FAIL();
        }

        //fprintf(stderr, "test #%3d - OK\n", n_test);
        n_test++;
    }
    SUCCEED();
}

TEST_F(SHA256Test, Sha256LongMsg){
    int n_test = 1;
    while (!feof(ftestlong))
    {
        ByteBlock msg_block, md_block, result_block;
        try {
            handle_test(msg_block, md_block, result_block, ftestlong);
        } catch(...) {
            fprintf(stderr, "%s\n", "Something wrong here...");
        }

        if (!equal(md_block, result_block))
        {
            print_difference(md_block, result_block, n_test);
            FAIL();
        }

        n_test++;
    }
    SUCCEED();
}
