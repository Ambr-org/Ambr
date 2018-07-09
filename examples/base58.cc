//here some example
#include <iostream>
#include <string>
#include "../src/crypto/base58.h"
#include <vector>

int main() {
    std::string input = "xbnbbmhgxxx76th65265kl.l$%^&&*(((,./,/,/,.,/";
    std::cout<<"Inputed: "<<input<<std::endl;

    std::string output;
    auto data = ambr::crypto::base58_encode((unsigned char*)input.c_str(), (unsigned char*)input.c_str() + input.size());
    std::cout<<"data:"<<data<<std::endl;

    std::vector<unsigned char> decoded;
    if (ambr::crypto::base58_decode(data, decoded)) {
        decoded.push_back('\0');
        std::cout<<"Decoded: "<<(char*)&decoded[0]<<std::endl;
    }

    return 0;
}