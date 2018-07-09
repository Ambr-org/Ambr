

#include <iostream>
#include <time.h>

#include "platform.h"

namespace ambr {
namespace arch {

std::string test() {

    time_t rawtime;
    time(&rawtime);  

    struct tm * timeinfo = localtime(&rawtime);  
    return std::string("Welcome to Ambr: ") + asctime(timeinfo);
}

};
};
