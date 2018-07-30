/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include "node.h"

#include <string>
#include <sstream>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <store/store_manager.h>
namespace pt = boost::property_tree;
/*
action:get_address_by_pub_key
param:pub_key

action:get_pub_key_by_address
param:account

action:create_pri_key
param:

action:get_balance_by_pub_key
param:pub_key

action:send_to
param: amount
      dest
      pri_key

TODO:
action:receive_from
param: unit_hash
      pri_key

all_return
      result:true false
      msg:right message or error message balabala
*/

std::string CmdSendTo(boost::property_tree::ptree pt){
  std::string result;
  std::string rtn_msg;
  boost::property_tree::ptree pt_child = pt.get_child("param");
  boost::multiprecision::uint128_t param_amount = pt_child.get<boost::multiprecision::uint128_t>("amount");
  std::string param_dest = pt_child.get<std::string>("dest");
  std::string param_pri_key = pt_child.get<std::string>("pri_key");
  ambr::core::PrivateKey pri_key = param_dest;
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);;
  ambr::core::UnitHash hash;
  ambr::core::Amount amount = boost::multiprecision::uint128_t(0);
  if(!ambr::store::GetStoreManager()->GetLastUnitHashByPubKey(pub_key, hash)){
    result = "false";
    rtn_msg = "Private key is not found!";
    return std::string("{")+"\"result\":"+result+",\"rtn_msg\":\""+rtn_msg+"\"}";
  }
  ambr::store::GetStoreManager()->GetBalanceByPubKey(pub_key, amount);
  if(param_amount > amount.data()){
    result = "false";
    rtn_msg = "Insufficient Balance!";
    return std::string("{")+"\"result\":"+result+",\"rtn_msg\":\""+rtn_msg+"\"}";
  }
  std::shared_ptr<ambr::core::SendUnit> unit =
  std::make_shared<ambr::core::SendUnit>();

  unit->set_version(0x00000001);
  unit->set_type(ambr::core::UnitType::send);
  unit->set_public_key(pub_key);
  unit->set_prev_unit(hash);
  unit->set_balance(param_amount - amount.data());
  //TODO
  //unit->set_dest(ambr::core::uni);
  unit->CalcHashAndFill();
  unit->SignatureAndFill(pri_key);
  result = "true";
  rtn_msg = unit->SerializeJson();
  return std::string("{")+"\"result\":"+result+",\"rtn_msg\":\""+rtn_msg+"\"}";
}


std::string ambr::core::ParserArgs(const std::string &  str){
  pt::ptree pt;
  std::istringstream stream(str);
  pt::read_json(stream, pt);

  std::string result;
  std::string rtn_msg;
  try{
    std::string cmd = pt.get<std::string>("action");
    if(cmd=="get_address_by_pub_key"){
      pt::ptree pt_child = pt.get_child("param");
      std::string param_pub_key = pt_child.get<std::string>("pub_key");
          
      std::stringstream ostream;
      pt::ptree root;
      ambr::core::PublicKey pub_key = param_pub_key;
      std::string&& addr = ambr::core::GetAddressStringByPublicKey(pub_key);
      if(0 < addr.size()){
        root.put("result", true);
        root.put("rtn_msg", addr);
      }
      else{
        root.put("result", false);
        root.put("rtn_msg", "Address key is not get!");
      }

      pt::write_json(ostream, root);
        return ostream.str();

    }else if(cmd == "get_pub_key_by_address"){
      pt::ptree pt_child = pt.get_child("param");
      std::string addr = pt_child.get<std::string>("address");
          
      std::stringstream ostream;
      pt::ptree root;
      ambr::core::PublicKey&& pub_key = ambr::core::GetPublicKeyByAddress(addr);
      if(0 < pub_key.bytes().size()){
        root.put("result", true);
        root.put("rtn_msg", pub_key.encode_to_hex());
      }
      else{
        root.put("result", false);
        root.put("rtn_msg", "Public key is not get!");
      }

      pt::write_json(ostream, root);
      return ostream.str();

      }else if(cmd == "create_pri_key"){
        std::stringstream ostream;
        pt::ptree root;
        ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
        if(0 < pri_key.bytes().size()){
        root.put("result", true);
        root.put("rtn_msg", pri_key.encode_to_hex());
      }
      else{
        root.put("result", false);
        root.put("rtn_msg", "Private key is not created!");
      }
          
      pt::write_json(ostream, root);
      return ostream.str();

      }else if(cmd == "get_balance_by_pub_key"){
        //lihn TODO
      }else if(cmd=="send_to"){
        return CmdSendTo(pt);
      }
      else{
        result = "false";
        rtn_msg = "Unkown cmd!";
        return std::string("{")+"\"result\":"+result+",\"rtn_msg\":\""+rtn_msg+"\"}";
      }
  }catch(...){
    result = "false";
    rtn_msg = "Parser param error!";
    return std::string("{")+"\"result\":"+result+",\"rtn_msg\":\""+rtn_msg+"\"}";
  }
  return  std::string();
}

