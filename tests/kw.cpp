#include <gtest/gtest.h>
#include <MyCryptoLib/mycrypto.hpp>
#include <MyCryptoLib/kw.hpp>

class KWTest : public testing::Test {
public:
    static FILE * file;

    static void SetUpTestCase()
    {
        char dir[1024];
        getcwd(dir, sizeof dir);
        fprintf(stderr, "cwd: %s\n", dir);
        file = fopen("kwdata/KW_AE_256.txt", "r");
    }
    static void TearDownTestCase()
    {
        fclose(file);
    }
};

class KWPTest : public testing::Test {
public:
    static FILE * file;

    static void SetUpTestCase()
    {
        file = fopen("kwdata/KWP_AE_256.txt", "r");
    }
    static void TearDownTestCase()
    {
        fclose(file);
    }
};

FILE * KWPTest::file = NULL;
FILE * KWTest::file = NULL;

static
bool handle_test(
    ByteBlock & pt,
    ByteBlock & ct,
    ByteBlock & key,
    FILE * f
) {
    char spt[1024], sct[1024], skey[1024];

    int read = 0;
    while(!feof(f)) {
        read = fscanf(f, "K = %s\n", skey);
        if(read) break;
        char temp[1024];
        fscanf(f, "%s\n", temp);
    }
    if(!read) return false;
    key = hex_to_bytes(skey);

    fscanf(f, "P = %s\n", spt);
    pt = hex_to_bytes(spt);

    fscanf(f, "C = %s\n", sct);
    ct = hex_to_bytes(sct);
    return true;
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

TEST_F(KWTest, FromFile) {
    int n_test = 1;
    ByteBlock pt, ct, key, result;

    while(handle_test(pt, ct, key, file))
    {
        try {
            KeyWrapFunction(result, pt, key);
        } catch( std::exception& e) {
            fprintf(stderr, "%d: %s\n", n_test, e.what());
        }

        if (!equal(result, ct))
        {
            print_difference(ct, result, n_test);
            FAIL();
        }
        n_test++;
    }

    SUCCEED();
}

TEST_F(KWPTest, FromFile) {
    int n_test = 1;
    ByteBlock pt, ct, key, result;

    while(handle_test(pt, ct, key, file))
    {
        try {
            KeyWrapPaddedFunction(result, pt, key);
        } catch( std::exception& e) {
            fprintf(stderr, "%d: %s\n", n_test, e.what());
        }

        if (!equal(result, ct))
        {
            print_difference(ct, result, n_test);
            FAIL();
        }
        n_test++;
    }

    SUCCEED();
}
