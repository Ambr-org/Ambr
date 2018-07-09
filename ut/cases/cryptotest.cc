
#include <sha256.h>
#include <base64.h>
#include <base58.h>
#include <gtest/gtest.h>

TEST(SHA256Test, HandleTrueReturn)
{
    std::string line = "hello, this is a test";
    ambr::crypto::SHA256OneByOneHasher hasher;
    //reset hasher state
    hasher.init(); 
    hasher.process(line.begin(), line.end());
    hasher.finish();

    std::string hex_str;
    ambr::crypto::get_hash_hex_string(hasher, hex_str);
    //std::cout<<hex_str.size()<<std::endl;
    EXPECT_TRUE(hex_str.size() == 64);
}

TEST(BASE64Test, HandleTrueReturn)
{
    std::string input = "base64 string";
    std::string output;
    ambr::crypto::base64_encode(input.c_str(), 
        input.size(), output);
    
    std::string decoded;
    ambr::crypto::base64_decode(output.c_str(), 
        output.size(), decoded);
    //std::cout<<"x:"<<input<<std::endl;
    std::cout<<"y:"<<decoded<<std::endl;
    EXPECT_TRUE(input == decoded);
}

TEST(BASE58Test, HandleTrueReturn)
{
    std::string input = "base58 string";
    std::string output = ambr::crypto::base58_encode(
        (unsigned char*)input.c_str(), 
        (unsigned char*)input.c_str() + input.size());
    
    std::vector<unsigned char> decoded;
    EXPECT_TRUE(ambr::crypto::base58_decode(output, decoded));
    
    decoded.push_back('\0');
    EXPECT_TRUE(input == (char*)&decoded[0]);
}
/*
TEST_P(IsPrimeParamTest, HandleTrueReturn)
{
    int n =  GetParam();
    EXPECT_TRUE(IsPrime(n));
}
INSTANTIATE_TEST_CASE_P(TrueReturn, IsPrimeParamTest, testing::Values(3, 5, 11, 23, 17));

struct NumberPair
{
    NumberPair(int _a, int _b)
    {
        a = _a;
        b = _b;
    }
    int a;
    int b;
};

class FooParamTest : public ::testing::TestWithParam<NumberPair>
{
};

TEST_P(FooParamTest, HandleThreeReturn)
{
    FooCalc foo;
    NumberPair pair = GetParam();
    EXPECT_EQ(3, foo.Calc(pair.a, pair.b));
}
INSTANTIATE_TEST_CASE_P(ThreeReturn, FooParamTest, testing::Values(NumberPair(12, 15), NumberPair(18, 21)));
*/