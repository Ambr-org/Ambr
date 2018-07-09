#include "core/key.h"
#include "core/unit.h"
//#include "argon2/argon2.h"
#include "crypto/random.h"
#include "crypto/blake2/blake2.h"
#include "ed25519-donna/ed25519.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/property_tree/json_parser.hpp>

#define KDF_WORK 64 * 1024
typedef boost::multiprecision::uint256_t uint256_t;
typedef boost::multiprecision::uint512_t uint512_t;

using namespace ambr::crypto;

namespace ambr{ 
namespace core{

const uint8_t* kAddrLookup = reinterpret_cast<const uint8_t*>("13456789abcdefghijkmnopqrstuwxyz");
const uint8_t* kAddrReverse = reinterpret_cast<const uint8_t*>("~0~1234567~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~89:;<=>?@AB~CDEFGHIJK~LMNO~~~~~");

uint8_t AddrEncode (uint8_t value){
  assert (value < 32);
  return kAddrLookup[value];
}

uint8_t AddrDecode (uint8_t value){
  assert (value >= '0');
  assert (value <= '~');
  return kAddrReverse[value - 0x30] - 0x30;
}

PrivateKey CreateRandomPrivateKey (){
  PrivateKey number;

  std::array<uint8_t, 32>&& bytes = crypto::Random::CreateRandomArray<32>();
  number.set_bytes(bytes);
  return number;
}

std::string StringToHex(const std::string& input) {
    std::stringstream ss;
    std::string tmp, result;
    for(auto it : input){
        ss << std::hex << (int)it << std::endl;
        ss >> tmp;
        result += tmp;
    }

    return std::move(result);
}

std::string HexToString(const std::string& input) {
    std::string result;
    for (size_t i = 0; i < input.size(); i += 2){
        std::string&& str = input.substr(i, 2);
        char chr = (char) (int)strtol(str.c_str(), NULL, 16);
        result += chr;
    }

    return std::move(result);
}

PublicKey GetPublicKeyByPrivateKey (const PrivateKey& pri_key){	
  uint8_t src[32] = {0};
  uint8_t des[32] = {0};

  std::string&& private_key = pri_key.encode_to_hex();
  memcpy(src, private_key.c_str(), sizeof(src));
  ed25519_publickey(src, des);

  std::array<uint8_t, 32> bytes;
  memcpy(bytes.data(), des, sizeof(des));
 
  PublicKey public_key;
  public_key.set_bytes(bytes);
  return public_key;
}

std::string GetAddressStringByPublicKey (const PublicKey& pub_key){
  std::string result;
  result.reserve(64);
  const std::array<uint8_t, 32>& bytes = pub_key.bytes();

#if 0
  uint64_t check = 0;
  blake2b_state hash;
  blake2b_init(&hash, 5);
  blake2b_update(&hash, bytes.data(), bytes.size() * sizeof(uint8_t));
  blake2b_final(&hash, reinterpret_cast<uint8_t*>(&check), 5);
#else
  uint64_t check = 0;
  blake2b(reinterpret_cast<uint8_t*>(&check), 5, bytes.data(), bytes.size(), NULL, 0);
#endif

  uint512_t num_l(pub_key.data());
  num_l <<= 40;
  num_l |= uint512_t(check);
  for (size_t i = 0; i < 60; ++i){
    uint8_t num_in(num_l & static_cast<uint8_t>(0x1f));
    num_l >>= 5;
    result.push_back(AddrEncode(num_in));
  }
  
  return std::move("ambr_" + result);
}

PublicKey GetPublicKeyByAddress (const std::string& addr_hex){
  PublicKey pub_key;
  std::string addr = addr_hex;
  if("ambr_" == addr.substr(0, 5)){
    std::string&& pub_tmp = addr.substr(5, addr.size() - 5);
    std::reverse(pub_tmp.begin(), pub_tmp.end());
    uint512_t num_l;
    for(auto& it:pub_tmp){
      uint8_t byte(AddrDecode((uint8_t)it));
      num_l <<= 5;
			num_l += byte;
    }

	  utils::uint256&& unit_tmp = (num_l >> 40).convert_to<uint256_t>();
		const std::array<uint8_t, 32>& bytes = unit_tmp.bytes();
    pub_key.set_bytes(bytes);
  }

  return pub_key;
}

bool AddressIsValidate (const std::string& addr){
  bool result(addr.size () < 5);
  if (!result){
    bool prefix("ambr_" == addr.substr(0, 5));
	  bool test_prefix("test_" == addr.substr(0, 5));
	  result = (prefix && addr.size () != 64) || (test_prefix && addr.size () != 65);
	  if (!result){
	    if (prefix || test_prefix){
        std::string&& addr_tmp = addr.substr(5, addr.size() - 5);
        std::reverse(addr_tmp.begin(), addr_tmp.end());
	      uint512_t num_l;
		    for (auto it : addr_tmp){
		      uint8_t character = it;
		      result = character < 0x30 || character >= 0x80;
		      if (!result){
		        uint8_t byte (AddrDecode (character));
			      result = ('~' == byte);
			      if (!result){
			        num_l <<= 5;
			        num_l += byte;
			      }
		      }
		    }
		    if (!result){
		      utils::uint256 unit_tmp ;
          uint64_t validation = 0;
		      unit_tmp = (num_l >> 40).convert_to<uint256_t>();
          const std::array<uint8_t, 32>& bytes = unit_tmp.bytes();
		      uint64_t check (num_l & static_cast<uint64_t> (0xffffffffff));
		        
#if 0
		      blake2b_state hash;
		      blake2b_init (&hash, 5);
		      blake2b_update (&hash, bytes.data (), bytes.size ());
		      blake2b_final (&hash, reinterpret_cast<uint8_t *> (&validation), 5);
#else
          blake2b(reinterpret_cast<uint8_t*>(&validation), 5, bytes.data(), bytes.size(), NULL, 0);
#endif
		      result = (check != validation);
		    }
	      else{
	        result = true;
	      }
    }
    else{
      result = true;
    }
  }
}
  return result;
}   

Signature GetSignByPrivateKey(const uint8_t* buf, size_t length, const PrivateKey& pri_key){
  Signature sign;
  std::array<uint8_t, 64> array;
	PublicKey&& pub_key = GetPublicKeyByPrivateKey(pri_key);

  ed25519_sign(buf, length, pri_key.bytes().data(), pub_key.bytes().data(), array.data ());
  sign.set_bytes(array);
	return sign;
}

bool SymEncrypting(const utils::uint256& input, const std::string& password, utils::uint256& output){
  #if 0
  std::array<uint8_t, 32> bytes;
  bool ret = (0 == argon2_hash(1, KDF_WORK, 1, password.data(), password.size() * sizeof(uint8_t), input.bytes().data(), input.bytes().size() * sizeof(uint8_t), bytes.data(), bytes.size() * sizeof(uint8_t), NULL, 0, Argon2_d, 0x10));
  output.set_bytes(bytes);
  return ret;
  #else
  //TODO: add argon2
  #endif
  return true;
}

bool SignIsValidate(const uint8_t* buf, size_t length, const PublicKey& pub_key, const Signature& sign){
	return 0 == ed25519_sign_open(buf, length, pub_key.bytes().data (), sign.bytes().data ());
}

}
}    
