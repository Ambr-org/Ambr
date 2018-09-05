
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Written by kan                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

//TODO define 
#ifndef AMBR_SERVER_AMBRD_H_
#define AMBR_SERVER_AMBRD_H_

#include <crow.h>

namespace ambr {
namespace server {

//fucking test
int DoServer(const std::string& db_path, uint16_t rpc_port, uint16_t p2p_prot, const std::string& seed_ip, uint16_t seed_port);

};
};

#endif
