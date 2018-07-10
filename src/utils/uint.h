
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef AMBR_UTILS_UINT_H_
#define AMBR_UTILS_UINT_H_

#include <stdint.h>
#include <string>
#include <strstream>
#include <boost/multiprecision/cpp_int.hpp>
namespace ambr {
namespace utils {
template<typename T, uint32_t size>
union uint_tool{
public:
  typedef  T ValueType;
  typedef std::array<uint8_t, size> ArrayType;
  uint_tool () {
    clear();
  }

  uint_tool (const std::string& str_hex){
    decode_from_hex(str_hex);
  }

  uint_tool (const char* str_hex){
    decode_from_hex(std::string(str_hex));
  }

  uint_tool (const T& it){
    T num = it;
    for(int i = bytes_.size()-1; i >=0; i--){
      bytes_[i] = static_cast<uint8_t>(num & static_cast<uint8_t> (0xff));
      num >>= 8;
    }
  }

  uint_tool (const ArrayType& bytes){
    bytes_ = bytes;
  }
  uint_tool (const uint_tool<T, size> & it){
    memcpy(&this->bytes_, &it.bytes_, bytes_.size());
  }

  uint_tool (const uint_tool<T, size> && it){
    memcpy(&this->bytes_, &it.bytes_, bytes_.size());
  }

  uint_tool& operator = (const uint_tool<T, size> & it){
    memcpy(&this->bytes_, &it.bytes_, bytes_.size());
    return *this;
  }

  operator T(){
    return data();
  }

  bool operator== (uint_tool<T, size> const& it) const{
    return (memcmp(bytes_.begin(), it.bytes_.begin(), it.bytes_.size())==0)?true:false;
  }

  bool operator!= (uint_tool<T, size> const& it) const{
    return (memcmp(bytes_.data(), it.bytes_.data(), it.bytes_.size())==0)?false:true;
  }

  bool operator< (uint_tool<T, size> const& it) const{
    return data() < it.data();
  }

  std::string encode_to_hex () const{
    std::ostringstream stream;
    stream << std::hex << std::noshowbase << std::setw (bytes_.size()*2) << std::setfill ('0');
    stream << data();
    return stream.str();
  }

  bool decode_from_hex (std::string const &str_hex){
    std::stringstream stream(str_hex.c_str());
    T data;
    stream << std::hex << std::noshowbase;
    stream >> data;
    if(!stream.eof()){
      clear();
      return false;
    }
    *this = data;
    return true;
  }

  void clear (){
    memset(&bytes_, 0, bytes_.size());
  }

  bool is_zero () const{
    for(int i = 0; i < bytes_.size(); i++){
      if(bytes_[i]){
        return false;
      }
    }
    return true;
  }

  T data () const{
    T result = 0;
    int i = 0;
    for(i = 0; i < bytes_.size()-1; i++){
      result |= bytes_[i];
      result <<= 8;
    }
    result |= bytes_[i];
    return result;
  }

  void set_data(T const& data){
    *this = data;
  }

  const std::array<uint8_t, size>& bytes() const {
    return bytes_;
  }

  void set_bytes(std::array<uint8_t, size> const & bytes){
    bytes_ = bytes;
  }

  void set_bytes(const void* byte, size_t len){
    if(size == len){
      memcpy(bytes_.data(), byte, size);
    }
  }
private:
  std::array<uint8_t, size> bytes_;
};
typedef uint_tool<uint32_t, 4> uint32;
typedef uint_tool<uint64_t, 8> uint64;
typedef uint_tool<boost::multiprecision::uint128_t, 16> uint128;
typedef uint_tool<boost::multiprecision::uint256_t, 32> uint256;
typedef uint_tool<boost::multiprecision::uint512_t, 64> uint512;
typedef uint_tool<boost::multiprecision::uint1024_t, 128> uint1024;
}
}


#endif
