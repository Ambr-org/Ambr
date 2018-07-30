/**********************************************************************
 * Copyright (c) 2018 ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include "server_interface.h"
#include "server/ambrd.h"
#include "core/node.h"
   
ambr::server::ServerInterface::ServerInterface()
	:desc_("Command line options"){
	AddNodeOption();
}

std::string ambr::server::ServerInterface::GetHelpMsg(){
	return std::string();
}


std::string ambr::server::ServerInterface::ParserArgs(const std::string & option){
	return std::string();
}

std::string ambr::server::ServerInterface::ParserArgs(const std::string & option, const std::string & user){
	return std::string();
}

std::string ambr::server::ServerInterface::ParserArgs(const std::string & option, const std::string & src,
	const std::string & dst, const int & amount){
	return std::string();
}

std::string ambr::server::ServerInterface::ParserArgs(int argc, char* argv[]) {
	po::store(po::parse_command_line(argc, argv, desc_), vm_);
	po::notify(vm_);

	return HandleNodeOption();
}

std::string ambr::server::ServerInterface::HandleNodeOption(){
	std::string str;
	pt::ptree json;
	std::stringstream stream;

	if (vm_.count("help")) {
		stream << desc_ << std::endl;
		return stream.str();
	} else if (vm_.count("version")) {
		return "0.5";
	} else if (vm_.count("daemon")) {
		ambr::server::DoServer();
		return "";
	} else if (vm_.count("get_address")) {
		if (vm_.count("key")) {
			std::stringstream ostream;
			pt::ptree tree, params;
			tree.put("action", "get_address_by_pub_key");
			params.put("key", vm_["key"].as<std::string>());
			tree.put_child("param", params);
			pt::write_json(ostream, tree);
			auto info = ambr::core::ParserArgs(ostream.str());
			std::stringstream istream(info);
			pt::read_json(istream, json);
			return json.get<std::string>("rtn_msg");
		} else {
			return "Please supply a key for address .";
		}
	} else if (vm_.count("get_balance")) {
		if (vm_.count("key")) {
			std::stringstream ostream;
			pt::ptree tree;
			tree.put("action", "get_balance");
			tree.put("key", vm_["key"].as<std::string>());
			pt::write_json(ostream, tree);
			auto info = ambr::core::ParserArgs(ostream.str());
			std::stringstream istream(info);
			pt::read_json(istream, json);
			return json.get<std::string>("balance");
		} else {
			return "Please supply a key for account .";
		}
	} else if (vm_.count("get_pubkey")) {
		if (vm_.count("address")) {
			std::stringstream ostream;
			pt::ptree tree, params;
			tree.put("action", "get_pub_key_by_address");
			params.put("address", vm_["address"].as<std::string>());
			tree.put_child("param", params);
			pt::write_json(ostream, tree);
			auto info = ambr::core::ParserArgs(ostream.str());
			std::stringstream istream(info);
			pt::read_json(istream, json);
			return  json.get<std::string>("rtn_msg");
		} else {
			return  "Please supply a address .";
		}

	} else if (vm_.count("create_pri_key")) {
		std::stringstream ostream;
		pt::ptree tree;
		tree.put("action", "create_pri_key");
		pt::write_json(ostream, tree);
		auto info = ambr::core::ParserArgs(ostream.str());
		std::stringstream istream(info);
		pt::read_json(istream, json);
		return json.get<std::string>("rtn_msg");
	} else if (vm_.count("create_wallet")) {
		std::stringstream ostream;
		pt::ptree tree;
		tree.put("action", "create_wallet");
		pt::write_json(ostream, tree);
		auto info = ambr::core::ParserArgs(ostream.str());
		std::stringstream istream(info);
		pt::read_json(istream, json);
		return json.get<std::string>("wallet");
	} else if (vm_.count("send")) {
		if (vm_.count("source") && vm_.count("destination") && vm_.count("amount")) {
			std::stringstream ostream;
			pt::ptree tree, params;
			tree.put("action", "send_to");
			params.put("pri_key", vm_["source"].as<std::string>());
			params.put("dest", vm_["destination"].as<std::string>());
			params.put("amount", vm_["amount"].as<int>());
			tree.put_child("param", params);
			pt::write_json(ostream, tree);
			auto info = ambr::core::ParserArgs(ostream.str());

			std::stringstream istream(info);
			pt::read_json(istream, json);
			if (json.get<bool>("result")) {
				return "Send success";
			}
			else {
				return "Send failed";
			}
		}
		else {
			return "Please supply source,dest and amount options ." ;
		}
	} else {
		stream << desc_ << std::endl;
		return stream.str();
	}
}

void ambr::server::ServerInterface::AddNodeOption() {
	desc_.add_options()
	("help,h", "Print out options")
	("version,v", "Prints out version")
	("daemon,d", "Start node daemon")
	("address", po::value<std::string>(), "Defines address for other use")
	("key", po::value<std::string>(), "Defines the key for other use")
	("wallet", po::value<std::string>(), "Defines wallet for other use")
	("source", po::value<std::string>(), "the source that send the ambr")
	("destination", po::value<std::string>(), "the source that get the ambr")
	("amount", po::value<int>(), "how much ambrs send")
	("list_wallet", "list wallet infomation")
	("generate_key", "Generates a adhoc random keypair and prints it to stdout")
	("get_address", "Get address by a specific pubkey")
	("get_pubkey", "Get the public key by a specific address")
	("data_path", boost::program_options::value<std::string>(), "Use the supplied path as the data directory")
	("create_wallet", "Creates a new wallet and prints the ID")
	("create_pri_key", "Creates a private key")
	("snapshot", "Compact database and get current database snapshot")
	("get_balance", "get balance from a specific key")
	("remove_account", "Remove a account from a specific wallet")
	("send", "send ambr to someone")
	;

}