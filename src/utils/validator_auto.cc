#include "validator_auto.h"
#include <boost/thread.hpp>
#include <boost/date_time.hpp>
#include <iostream>
#include <store/store_manager.h>
#include <glog/logging.h>
ambr::utils::ValidatorAuto::ValidatorAuto(std::shared_ptr<store::StoreManager> store_manager):
  store_manager_(store_manager),
  thread_(nullptr){
  assert(store_manager_);

}

void ambr::utils::ValidatorAuto::StartAutoRun(const ambr::core::PrivateKey &pri_key){
  if(thread_)StopAutoRun();
  run_ = true;
  thread_ = new std::thread([&,pri_key](){
    uint64_t last_nonce = 0;
    uint64_t now_nonce = 0;
    uint64_t interval = 0;
    while(run_){
      boost::posix_time::ptime pt = boost::posix_time::microsec_clock::universal_time();
      boost::posix_time::ptime pt_ori(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
      boost::posix_time::time_duration duration = pt-pt_ori;
      interval = duration.total_milliseconds() - ambr::store::GetStoreManager()->GetGenesisTime();
      now_nonce = (interval/publish_interval_);
      if(now_nonce > last_nonce){
        last_nonce = now_nonce;
        //std::cout<<interval<<":"<<now_nonce<<std::endl;
        ambr::core::PublicKey now_pub_key;
        if(ambr::store::GetStoreManager()->GetValidatorSet()->GetNonceTurnValidator(now_nonce, now_pub_key)){
          if(now_pub_key == ambr::core::GetPublicKeyByPrivateKey(pri_key)){
            std::cout<<"MyTurns:"<<now_pub_key.encode_to_hex()<<std::endl;
            core::UnitHash tx_hash;
            std::shared_ptr<ambr::core::ValidatorUnit> unit_validator;
            std::string err;
            if(ambr::store::GetStoreManager()->PublishValidator(pri_key, &tx_hash, unit_validator, &err)){
              LOG(INFO)<<"Send Validator Success, tx_hash:"<<tx_hash.encode_to_hex()<<",public:"<<now_pub_key.encode_to_hex()<<std::endl;
            }else{
              LOG(WARNING)<<"Send Validator Faild,public:"<<now_pub_key.encode_to_hex()<<std::endl;
            }
          }
        }
      }
      boost::this_thread::sleep(boost::posix_time::millisec(100));
    }
  });
}

void ambr::utils::ValidatorAuto::StopAutoRun(){
  run_ = false;
  thread_->join();
  delete thread_;
  thread_ = nullptr;
}
