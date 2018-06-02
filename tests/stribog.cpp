#include <gtest/gtest.h>
#include <cstdio>
#include <MyCryptoLib/Stribog.hpp>

class Stribog256Test : public testing::Test {
public:
    static FILE * ftest;

    static void SetUpTestCase()
    {
        ftest = fopen("gost3411data/gost_3411_256.txt", "r");
    }
    static void TearDownTestCase()
    {
        fclose(ftest);
    }
};

class Stribog512Test : public testing::Test {
public:
    static FILE * ftest;

    static void SetUpTestCase()
    {
        ftest = fopen("gost3411data/gost_3411_512.txt", "r");
    }
    static void TearDownTestCase()
    {
        fclose(ftest);
    }
};

FILE * Stribog256Test::ftest = NULL;
FILE * Stribog512Test::ftest = NULL;

static
void print_difference(ByteBlock const & exp, ByteBlock const & res, int n_test)
{
    fprintf(stderr, "\n");
    fprintf(stderr, "-=-=-=- test #%d -=-=-=-\n", n_test);
    fprintf(stderr, "Expected: %s\n", hex_representation(exp).c_str());
    fprintf(stderr, "Result:   %s\n", hex_representation(res).c_str());
    fprintf(stderr, "\n");
}

TEST_F(Stribog256Test, MainTest) {
    int n_test = 1;
    while (!feof(ftest))
    {
        ByteBlock msg_block, md_block, result_block;
        try {
            Stribog256 algorithm;

            char msg_str [10240];
            fscanf(ftest, "InputText=%s\n", msg_str);
            msg_block = hex_to_bytes(msg_str, strlen(msg_str));

            char md[32 * 2 + 1];
            fscanf(ftest, "DigestValue=%s\n\n", md);
            md_block = hex_to_bytes(md, 32 * 2);

            algorithm.hash(msg_block, result_block);
        } catch(std::exception & e) {
            fprintf(stderr, "test #%d: %s\n",n_test, e.what());
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

TEST_F(Stribog256Test, ZeroMsg) {
    ByteBlock md_block = hex_to_bytes(
            "BBE19C8D2025D99F943A932A0B365A822AA36A4C479D22CC02C8973E219A533F"
    );
    ByteBlock result_block;
    Stribog256 alg;
    alg.hash(ByteBlock(), result_block);

    if (!equal(md_block, result_block))
    {
        print_difference(md_block, result_block, 0);
        FAIL();
    }
    SUCCEED();
}

TEST_F(Stribog512Test, MainTest) {
    int n_test = 1;
    while (!feof(ftest))
    {
        ByteBlock msg_block, md_block, result_block;
        try {
            Stribog512 algorithm;

            char msg_str [10240];
            fscanf(ftest, "InputText=%s\n", msg_str);
            msg_block = hex_to_bytes(msg_str, strlen(msg_str));

            char md[32 * 4 + 1];
            fscanf(ftest, "DigestValue=%s\n\n", md);
            md_block = hex_to_bytes(md, 32 * 4);

            algorithm.hash(msg_block, result_block);
        } catch(std::exception & e) {
            fprintf(stderr, "test #%d: %s\n",n_test, e.what());
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

TEST_F(Stribog512Test, ZeroMsg) {
    ByteBlock md_block = hex_to_bytes(
            "8A1A1C4CBF909F8ECB81CD1B5C713ABAD26A4CAC2A5FDA3CE86E352855712F36A7F0BE98EB6CF51553B507B73A87E97946AEBC29859255049F86AA09A25D948E"
    );
    ByteBlock result_block;
    Stribog512 alg;
    alg.hash(ByteBlock(), result_block);

    if (!equal(md_block, result_block))
    {
        print_difference(md_block, result_block, 0);
        FAIL();
    }
    SUCCEED();
}
