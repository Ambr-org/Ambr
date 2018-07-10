
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef AMBR_CORE_KEY_H_
#define AMBR_CORE_KEY_H_
#include "utils/uint.h"

namespace ambr {
namespace core {

typedef utils::uint256 Address;
typedef utils::uint256 PublicKey;
typedef utils::uint256 PrivateKey;
typedef utils::uint512 Signature;
typedef utils::uint256 UnitHash;
typedef utils::uint128 Amount;

uint8_t AddrEncode(uint8_t value);

uint8_t AddrDecode(uint8_t value);

PrivateKey CreateRandomPrivateKey();

bool AddressIsValidate(const std::string& addr);

std::string StringToHex(const std::string& input);

std::string HexToString(const std::string& input);

PublicKey GetPublicKeyByAddress (const std::string& addr_hex);

std::string GetAddressStringByPublicKey(const PublicKey& pub_key);

PublicKey GetPublicKeyByPrivateKey(const PrivateKey& pri_key);

Signature GetSignByPrivateKey(const uint8_t* buf, size_t length, const PrivateKey& pri_key);

bool SymEncrypting(const utils::uint256& input, const std::string& password, utils::uint256& output);

bool SignIsValidate(const uint8_t* buf, size_t length, const PublicKey& pub_key, const Signature& sign);
}}

#endif
