#include <gtest/gtest.h>
#include <MyCryptoLib/mycrypto.hpp>
#include <MyCryptoLib/kw.hpp>

class KUWTest : public testing::Test {
public:
    static FILE * file;

    static void SetUpTestCase()
    {
        file = fopen("kwdata/KW_AD_256.txt", "r");
    }
    static void TearDownTestCase()
    {
        fclose(file);
    }
};

class KUWPTest : public testing::Test {
public:
    static FILE * file;

    static void SetUpTestCase()
    {
        file = fopen("kwdata/KWP_AD_256.txt", "r");
    }
    static void TearDownTestCase()
    {
        fclose(file);
    }
};

FILE * KUWPTest::file = NULL;
FILE * KUWTest::file = NULL;

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

    fscanf(f, "C = %s\n", sct);
    ct = hex_to_bytes(sct);

    if(fscanf(f, "P = %s\n", spt))
        pt = hex_to_bytes(spt);
    else
        pt.reset(NULL, 0);

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

TEST_F(KUWTest, FromFile) {
    int n_test = 1;
    ByteBlock pt, ct, key, result;

    while(handle_test(pt, ct, key, file))
    {
        bool success = true;
        try {
            try {
                KeyUnwrapFunction(result, ct, key);
                if(pt.byte_ptr() == NULL)
                    success = false;
            } catch(std::invalid_argument &) {
                if(pt.byte_ptr() != NULL) {
                    success = false;
                    throw;
                } else {
                    result.reset(NULL, 0);
                }
            }
        } catch(std::exception& e) {
            fprintf(stderr, "%d: %s\n", n_test, e.what());
        }

        if (!success || !equal(result, pt))
        {
            print_difference(pt, result, n_test);
            FAIL();
        }
        n_test++;
    }

    SUCCEED();
}

TEST_F(KUWPTest, FromFile) {
    int n_test = 1;
    ByteBlock pt, ct, key, result;

    while(handle_test(pt, ct, key, file))
    {
        bool success = true;
        try {
            try {
                KeyUnwrapPaddedFunction(result, ct, key);
                if(pt.byte_ptr() == NULL)
                    success = false;
            } catch(std::invalid_argument &) {
                if(pt.byte_ptr() != NULL) {
                    success = false;
                    throw;
                } else {
                    result.reset(NULL, 0);
                }
            }
        } catch( std::exception& e) {
            fprintf(stderr, "%d: %s\n", n_test, e.what());
        }

        if (!success || !equal(result, pt))
        {
            print_difference(pt, result, n_test);
            FAIL();
        }
        n_test++;
    }

    SUCCEED();
}
