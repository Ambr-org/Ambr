#include "validator_auto.h"
#include <boost/thread.hpp>
#include <boost/date_time.hpp>
#include <iostream>
#include <store/store_manager.h>
#include <glog/logging.h>
ambr::utils::ValidatorAuto::ValidatorAuto(std::shared_ptr<store::StoreManager> store_manager):
  store_manager_(store_manager),
  thread_(nullptr),
  run_(false){
  assert(store_manager_);
}

ambr::utils::ValidatorAuto::~ValidatorAuto(){
}

void ambr::utils::ValidatorAuto::StartAutoRun(const ambr::core::PrivateKey &pri_key){
  private_key_ = pri_key;
  if(thread_)StopAutoRun();

  run_ = true;
  thread_ = new std::thread([&,pri_key](){
    uint64_t last_nonce = 0;
    uint64_t now_nonce = 0;
    uint64_t interval = 0;
    boost::signals2::connection connection = store_manager_->AddCallBackReceiveNewValidatorUnit(boost::bind(&ambr::utils::ValidatorAuto::OnNeedVote, this, _1));
    while(run_){
      boost::posix_time::ptime pt = boost::posix_time::microsec_clock::universal_time();
      boost::posix_time::ptime pt_ori(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
      boost::posix_time::time_duration duration = pt-pt_ori;
      interval = duration.total_milliseconds() - store_manager_->GetGenesisTime();
      now_nonce = (interval/store_manager_->GetValidateUnitInterval());
      if(now_nonce > last_nonce){
        last_nonce = now_nonce;
        //std::cout<<interval<<":"<<now_nonce<<std::endl;
        ambr::core::PublicKey now_pub_key;
        if(store_manager_->GetValidatorSet()->GetNonceTurnValidator(now_nonce, now_pub_key)){
          if(now_pub_key == ambr::core::GetPublicKeyByPrivateKey(pri_key)){
            std::cout<<"MyTurns:"<<now_pub_key.encode_to_hex()<<std::endl;
            core::UnitHash tx_hash;
            std::shared_ptr<ambr::core::ValidatorUnit> unit_validator;
            std::string err;
            if(store_manager_->PublishValidator(pri_key, &tx_hash, unit_validator, &err)){
              LOG(INFO)<<"Send Validator Success, tx_hash:"<<tx_hash.encode_to_hex()<<",public:"<<now_pub_key.encode_to_hex()<<std::endl;
            }else{
              LOG(WARNING)<<"Send Validator Faild,public:"<<now_pub_key.encode_to_hex()<<err<<std::endl;
            }
          }
        }
      }
      boost::this_thread::sleep(boost::posix_time::millisec(100));
    }
    connection.disconnect();
  });
}

void ambr::utils::ValidatorAuto::StopAutoRun(){
  if(thread_){
    run_ = false;
    thread_->join();
    delete thread_;
    thread_ = nullptr;
  }
}

void ambr::utils::ValidatorAuto::OnNeedVote(std::shared_ptr<ambr::core::ValidatorUnit> validator_unit){
  std::shared_ptr<core::VoteUnit> vote_unit;
  std::string err;
  if(!validator_unit)return;
  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set = store_manager_->GetValidatorSet();
  if(!validator_set)return;
  if(validator_set->IsValidator(core::GetPublicKeyByPrivateKey(private_key_), validator_unit->nonce())){
    if(!store_manager_->PublishVote(private_key_, true, vote_unit, &err)){
      LOG(ERROR)<<"Auto vote err:"<<err;
    }
  }
}
