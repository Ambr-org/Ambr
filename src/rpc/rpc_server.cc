#include "rpc_server.h"
#include <boost/thread.hpp>
using namespace ambr::rpc;
grpc::Status RpcServer::AddSendUnitByJson(grpc::ServerContext *context, const ambr::rpc::AddUnitRequest *request, ambr::rpc::AddUnitReply *response)
{
  std::shared_ptr<ambr::core::SendUnit> send_unit = std::make_shared<ambr::core::SendUnit>();
  std::string error;
  if(!send_unit->DeSerializeJson(request->json())){
    error = "Error json format";
  }else if(store_manager_->AddSendUnit(send_unit, &error)){
    response->set_result(true);
    response->set_error_message("");
    return grpc::Status::OK;
  }

  response->set_result(false);
  response->set_error_message(error);
  return grpc::Status::OK;
}

grpc::Status RpcServer::AddReceiveUnitByJson(grpc::ServerContext *context, const ambr::rpc::AddUnitRequest *request, ambr::rpc::AddUnitReply *response){
  std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::make_shared<ambr::core::ReceiveUnit>();
  std::string error;
  if(!receive_unit->DeSerializeJson(request->json())){
    error = "Error json format";
  }else if(store_manager_->AddReceiveUnit(receive_unit, &error)){
    response->set_result(true);
    response->set_error_message("");
    return grpc::Status::OK;
  }

  response->set_result(false);
  response->set_error_message(error);
  return grpc::Status::OK;
}

grpc::Status RpcServer::GetWaitForReceiveUnit(grpc::ServerContext *context, const ambr::rpc::GetWaitForReceiveUnitRequest *request, ambr::rpc::GetWaitForReceiveUnitReply *response){
  ambr::core::PublicKey pub_key;
  pub_key.decode_from_hex(request->public_key());
  std::list<ambr::core::UnitHash> unit_hash_list = store_manager_->GetWaitForReceiveList(pub_key);
  response->set_result(true);
  for(auto iter = unit_hash_list.begin(); iter != unit_hash_list.end(); iter++){
    ambr::core::Amount amount;
    assert(store_manager_->GetSendAmount(*iter, amount, nullptr));
    auto item_p = response->add_items();
    item_p->set_hash(iter->encode_to_hex());
    item_p->set_amount(amount.encode_to_dec());
  }
  return grpc::Status::OK;
}

grpc::Status RpcServer::GetBalance(grpc::ServerContext *context, const ambr::rpc::GetBalanceRequest *request, ambr::rpc::GetBalanceReply *response){
  ambr::core::PublicKey pub_key;
  pub_key.decode_from_hex(request->public_key());
  ambr::core::Amount balance;
  if(store_manager_->GetBalanceByPubKey(pub_key, balance)){
    response->set_result(true);
    response->set_amount(balance.encode_to_dec());
  }else{
    response->set_result(false);
    response->set_error_message("no account");
  }
  return grpc::Status::OK;
}

grpc::Status RpcServer::GetHistory(grpc::ServerContext *context, const ambr::rpc::GetHistoryRequest *request, ambr::rpc::GetHistoryReply *response){
  ambr::core::PublicKey pub_key;
  pub_key.decode_from_hex(request->public_key());
  std::string error;
  std::list<std::shared_ptr<ambr::store::UnitStore> > store_list = store_manager_->GetTradeHistoryByPubKey(pub_key, 100);
  for(std::shared_ptr<ambr::store::UnitStore> store_item: store_list){

    if(store_item->type() == ambr::store::UnitStore::ST_SendUnit){
      auto itemp = response->add_items();
      std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(store_item->GetUnit());
      if(send_unit->data_type() == ambr::core::SendUnit::DataType::Message){
        itemp->set_type("message");
      }else{
        itemp->set_type("send");
      }
      ambr::core::Amount amount;
      if(store_manager_->GetSendAmountWithTransactionFee(store_item->GetUnit()->hash(), amount, &error)){
        itemp->set_amount(amount.encode_to_dec());
      }
      else{
        response->set_result(false);
        response->set_error_message(error);
        return grpc::Status::OK;
      }
    }else if(store_item->type() == ambr::store::UnitStore::ST_ReceiveUnit){
      auto itemp = response->add_items();
      itemp->set_type("receive");
      ambr::core::Amount amount;
      if(store_manager_->GetReceiveAmount(store_item->GetUnit()->hash(), amount, &error)){
        itemp->set_amount(amount.encode_to_dec());
      }
      else{
        response->set_result(false);
        response->set_error_message(error);
        return grpc::Status::OK;
      }
    }
  }
  response->set_result(true);
  return grpc::Status::OK;
}

grpc::Status RpcServer::SendMessage(grpc::ServerContext *context, const ambr::rpc::SendMessageRequest *request, ambr::rpc::SendMessageReply *response){
  std::shared_ptr<ambr::core::SendUnit> send_unit = std::make_shared<ambr::core::SendUnit>();
  std::string error;
  if(send_unit->DeSerializeJson(request->json())){
    error = "Error json format";
  }else if(store_manager_->AddSendUnit(send_unit, &error)){
    response->set_result(true);
    response->set_error_message("");
    return grpc::Status::OK;
  }

  response->set_result(false);
  response->set_error_message(error);
  return grpc::Status::OK;
}

grpc::Status RpcServer::GetMessageStream(grpc::ServerContext *context, const MessageStreamRequest *request, ::grpc::ServerWriter<MessageStreamReply> *writer){
  //writer->Write()
  bool connected = true;
  boost::signals2::connection connection = store_manager_->AddCallBackReceiveNewSendUnit([&](std::shared_ptr<ambr::core::SendUnit> send_unit){
    if(send_unit->data_type() == ambr::core::SendUnit::Message){
      MessageStreamReply reply;
      reply.set_public_key(send_unit->public_key().encode_to_hex());
      reply.set_message(send_unit->data());
      if(!writer->Write(reply)){
        connected = false;
        connection.disconnect();
      };
    }
  });
  while(!context->IsCancelled() && connected == true){
    boost::this_thread::sleep(boost::posix_time::millisec(100));
  }
  connection.disconnect();
  return grpc::Status::OK;
}

grpc::Status RpcServer::GetLastUnitHash(grpc::ServerContext *context, const GetLastUnitHashRequest *request, GetLastUnitHashReplay *response){
  ambr::core::PublicKey pub_key;
  pub_key.decode_from_hex(request->public_key());
  std::string error;
  ambr::core::UnitHash unit_hash;
  if(!store_manager_->GetLastUnitHashByPubKey(pub_key, unit_hash)){
    response->set_result(false);
    response->set_error_message("");
  }else{
    response->set_result(true);
    response->set_hash(unit_hash.encode_to_hex());
  }
  return grpc::Status::OK;
}

grpc::Status RpcServer::PubSendTransf(grpc::ServerContext *context, const PubSendTransfRequest *request, PubSendTransfReply *response){
  ambr::core::PrivateKey pri_key(request->private_key());
  ambr::core::PublicKey public_key(request->dest_public());
  ambr::core::Amount amount(atoll(request->amount().c_str()));

  std::string error;
  ambr::core::UnitHash unit_hash;
  std::shared_ptr<ambr::core::Unit> tmp_unit;
  if(!store_manager_->SendToAddress(public_key, amount, pri_key, &unit_hash, tmp_unit, &error)){
    response->set_result(false);
    response->set_error_message(error);
  }else{
    response->set_result(true);
    response->set_error_message(unit_hash.encode_to_hex());
  }
  return grpc::Status::OK;
}

grpc::Status RpcServer::PubReceiveTransf(grpc::ServerContext *context, const PubReceiveTransfRequest *request, PubReceiveTransfReply *response){
  ambr::core::PrivateKey pri_key(request->private_key());
  ambr::core::UnitHash from_hash(request->from_hash());

  std::string error;
  ambr::core::UnitHash unit_hash;
  std::shared_ptr<ambr::core::Unit> tmp_unit;
  if(!store_manager_->ReceiveFromUnitHash(from_hash, pri_key, &unit_hash, tmp_unit, &error)){
    response->set_result(false);
    response->set_error_message(error);
  }else{
    response->set_result(true);
    response->set_error_message(unit_hash.encode_to_hex());
  }
  return grpc::Status::OK;
}

grpc::Status RpcServer::PubSendMessage(grpc::ServerContext *context, const PubSendMessageRequest *request, PubSendMessageReply *response){
  ambr::core::PrivateKey pri_key(request->private_key());

  std::string error;
  ambr::core::UnitHash unit_hash;
  std::shared_ptr<ambr::core::Unit> tmp_unit;
  if(!store_manager_->SendMessage(pri_key, request->message(), &unit_hash, tmp_unit, &error)){
    response->set_result(false);
    response->set_error_message(error);
  }else{
    response->set_result(true);
    response->set_error_message(unit_hash.encode_to_hex());

  }
  return grpc::Status::OK;
}

RpcServer::RpcServer():rpc_thread_(nullptr),store_manager_(nullptr){

}

RpcServer::~RpcServer(){
  StopRpcServer();
}

bool RpcServer::StartRpcServer(std::shared_ptr<ambr::store::StoreManager> store_manager, uint16_t rpc_port){
  if(!rpc_thread_){
    rpc_thread_ = new std::thread(std::bind(&RpcServer::RpcThreadFunc, this, rpc_port));
  }
  store_manager_ = store_manager;

  return false;
}

void RpcServer::StopRpcServer(){
  rpc_server_->Shutdown();
  rpc_thread_->join();
  delete rpc_thread_;
  rpc_thread_ = nullptr;
}

void RpcServer::RpcThreadFunc(uint16_t rpc_port){
  std::string server_address = std::string("0.0.0.0:")+std::to_string(rpc_port);
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(this);
  rpc_server_ = builder.BuildAndStart();
  rpc_server_->Wait();
}
