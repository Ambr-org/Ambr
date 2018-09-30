#include "db.h"

#include <rocksdb/db.h>
#include <rocksdb/slice.h>
#include <rocksdb/options.h>

using namespace ambr::store;

class KeyValueDBInterface::WriteBatch::Impl{
public:
  bool Write(KeyValueDBInterface::TableHandle* table_handle, const std::string& key, const std::string& value){
    rocksdb::Status status = batch_.Put(table_handle, key, value);
    return status.ok();
  }
  bool Delete(KeyValueDBInterface::TableHandle* table_handle, const std::string& key){
    rocksdb::Status status = batch_.Delete(table_handle, key);
    return status.ok();
  }
public:
  ::rocksdb::WriteBatch batch_;
};

bool KeyValueDBInterface::WriteBatch::Write(KeyValueDBInterface::TableHandle *table_handle, const std::string &key, const std::string &value){
  return impl_->Write(table_handle, key, value);
}

bool KeyValueDBInterface::WriteBatch::Delete(KeyValueDBInterface::TableHandle *table_handle, const std::string &key){
  return true;
}

KeyValueDBInterface::WriteBatch::WriteBatch(){
  impl_ = new Impl();
}

KeyValueDBInterface::WriteBatch::~WriteBatch(){
  delete impl_;
}


class KeyValueDBInterface::Impl{
public:
  bool InitDB(const std::string& path,const std::vector<std::string>& table_name_list, std::vector<TableHandle*>* table_handle){
    rocksdb::DBOptions options;
    std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
    options.create_if_missing = true;
    options.create_missing_column_families = true;

    column_families.push_back(rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions()));
    for(const std::string& str_item:table_name_list){
      column_families.push_back(rocksdb::ColumnFamilyDescriptor(str_item, rocksdb::ColumnFamilyOptions()));
    }
    rocksdb::Status status = rocksdb::DB::Open(options, path, column_families, (std::vector<rocksdb::ColumnFamilyHandle*>*)table_handle, &db_);
    return status.ok();
  }
  TableHandle* GetTable(const std::string& table_name, bool b_create);
  bool Write(KeyValueDBInterface::TableHandle* table_handle, const std::string& key, const std::string& value){
    ::rocksdb::Status status = db_->Put(rocksdb::WriteOptions(), table_handle, key, value);
    return status.ok();
  }
  bool Read(KeyValueDBInterface::TableHandle* table_handle, const std::string& key, std::string& value){
    ::rocksdb::Status status = db_->Get(rocksdb::ReadOptions(), table_handle, key, &value);
    return status.ok();
  }
  // operator in brach is atom
  bool Write(WriteBatch& brach){
    ::rocksdb::Status status = db_->Write(rocksdb::WriteOptions(), &(brach.impl_->batch_));
    return status.ok();
  }

  void Foreach(KeyValueDBInterface::TableHandle* table_handle,
               std::function<bool(const std::string&/*key*/,
                                  const std::string&/*value*/)>
                callback
               ){
    rocksdb::Iterator* it = db_->NewIterator(rocksdb::ReadOptions(), table_handle);
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
      /*ambr::core::PublicKey pub_key;
      ambr::core::UnitHash unit_hash;
      pub_key.set_bytes(it->key().data(), it->key().size());
      unit_hash.set_bytes(it->value().data(), it->value().size());
      if(std::find(validator_check_list.begin(), validator_check_list.end(), unit_hash) != validator_check_list.end()){
        will_remove.push_back(pub_key);
      }*/
      if(!callback(std::string(it->key().data(), it->key().size()),
                   std::string(it->value().data(), it->value().size()))){
        break;
      }
    }
    delete it;
  }
public:
  rocksdb::DB* GetDBNavate(){
    return db_;
  }
public:
  Impl():db_(nullptr){}
  ~Impl(){
    if(db_){
      db_->Close();
    }
    delete db_;
  }
private:
  rocksdb::DB* db_;
};


bool KeyValueDBInterface::InitDB(const std::string& path,const std::vector<std::string>& table_name_list, std::vector<TableHandle*>* table_handle){
  return impl_->InitDB(path, table_name_list, table_handle);
}


bool KeyValueDBInterface::Write(KeyValueDBInterface::TableHandle *table_handle, const std::string &key, const std::string &value){
  return impl_->Write(table_handle, key, value);
}

bool KeyValueDBInterface::Read(KeyValueDBInterface::TableHandle *table_handle, const std::string &key, std::string &value){
  return impl_->Read(table_handle, key, value);
}

void KeyValueDBInterface::Foreach(KeyValueDBInterface::TableHandle *table_handle, std::function<bool (const std::string &, const std::string &)> callback){
  return impl_->Foreach(table_handle, callback);
}

bool KeyValueDBInterface::Write(KeyValueDBInterface::WriteBatch &brach){
  return impl_->Write(brach);
}

rocksdb::DB *KeyValueDBInterface::GetDBNavate()
{
  return impl_->GetDBNavate();
}

KeyValueDBInterface::KeyValueDBInterface(){
  impl_=new Impl();
}

KeyValueDBInterface::~KeyValueDBInterface(){
  delete impl_;
}
