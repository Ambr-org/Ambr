
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 **************************************************************************/
#include <iostream>
#include "../src/crypto/sha256.h"

int main() {
	std::cout << "Input freely. To get hash, input \"enter!\". " << std::endl;
	ambr::crypto::SHA256OneByOneHasher hasher;

	while(true){
        //reset hasher state
		hasher.init(); 
		while(true){
			std::string line;
			std::getline(std::cin, line);
			if(line.size() <= 0){
				break;
			}

			hasher.process(line.begin(), line.end());
		}

		hasher.finish();
		std::string hex_str;

		ambr::crypto::get_hash_hex_string(hasher, hex_str);
		std::cout << hex_str << std::endl;
	}

    return 0;
}
