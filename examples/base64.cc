
//here some example
#include <iostream>

#include "../src/crypto/base64.h"

int main() {
    std::string input = "xbnbbmhgxxx76th65265kl.l$%^&&*(((,./,/,/,.,/";
    std::cout<<"Inputed: "<<input<<std::endl;

    std::string output;
    if (ambr::crypto::base64_encode(input.c_str(), input.size(), output)) {
        std::cout<<"Encoded: "<<output.c_str()<<std::endl;
    }

    std::string decoded;
    if(ambr::crypto::base64_decode(output.c_str(), output.size(), decoded)) {
        std::cout<<"Decoded: "<<decoded.c_str()<<std::endl;
    }

    return 0;
}