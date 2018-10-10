#ifndef _DB_H_
#define _DB_H_
#include <string>
#include <vector>
#include <functional>
namespace ambr {
namespace store {

class KeyValueDBInterface{
public:
  class Impl;
  class TableHandle;
  class WriteBatch;
public:
  /**
   * @brief InitDB
   * @param[in] path db source file's path
   * @param[in] table_name_list db's table_name list
   * @param[out] table_handle db table's operator handle
   * @return  0 faild else success
   */
  bool InitDB(const std::string& path,const std::vector<std::string>& table_name_list, std::vector<TableHandle*>* table_handle);
  bool Write(TableHandle* table_handle, const std::string& key, const std::string& value);
  bool Read(TableHandle* table_handle, const std::string& key, std::string& value);
  /*
    foreach all iterator and call callback.
    break at  callback return false or iter at the end
  */
  void Foreach(TableHandle* table_handle,
               std::function<bool(const std::string&/*key*/,
                                  const std::string&/*value*/)>
                callback
               );
  // operator in brach is atom
  bool Write(WriteBatch& brach);
public:
  KeyValueDBInterface();
  ~KeyValueDBInterface();
private:
  Impl* impl_;
};

class KeyValueDBInterface::WriteBatch{
public:
  bool Write(KeyValueDBInterface::TableHandle* table_handle, const std::string& key, const std::string& value);
  bool Delete(KeyValueDBInterface::TableHandle* table_handle, const std::string& key);
public:
  WriteBatch();
  ~WriteBatch();
public:
  class Impl;
  Impl* impl_;
};

}
}

#endif
