#ifndef __RPC_SERVER__H__
#define __RPC_SERVER__H__
#include<thread>
#include <grpcpp/grpcpp.h>

#include "rpc.grpc.pb.h"
#include "store/store_manager.h"
namespace ambr{
namespace rpc{


class RpcServer final : public ambr::rpc::RpcInterface::Service {
public:
  virtual ::grpc::Status AddSendUnitByJson(::grpc::ServerContext* context, const ::ambr::rpc::AddUnitRequest* request, ::ambr::rpc::AddUnitReply* response) override;
  virtual ::grpc::Status AddReceiveUnitByJson(::grpc::ServerContext* context, const ::ambr::rpc::AddUnitRequest* request, ::ambr::rpc::AddUnitReply* response) override;
  virtual ::grpc::Status GetWaitForReceiveUnit(::grpc::ServerContext* context, const ::ambr::rpc::GetWaitForReceiveUnitRequest* request, ::ambr::rpc::GetWaitForReceiveUnitReply* response);
  virtual ::grpc::Status GetBalance(::grpc::ServerContext* context, const ::ambr::rpc::GetBalanceRequest* request, ::ambr::rpc::GetBalanceReply* response) override;
  virtual ::grpc::Status GetHistory(::grpc::ServerContext* context, const ::ambr::rpc::GetHistoryRequest* request, ::ambr::rpc::GetHistoryReply* response) override;
  virtual ::grpc::Status SendMessage(::grpc::ServerContext* context, const ::ambr::rpc::SendMessageRequest* request, ::ambr::rpc::SendMessageReply* response) override;
  virtual ::grpc::Status GetLastUnitHash(::grpc::ServerContext* context, const ::ambr::rpc::GetLastUnitHashRequest* request, ::ambr::rpc::GetLastUnitHashReplay* response) override;
public:
  RpcServer();
  ~RpcServer();
  bool StartRpcServer(std::shared_ptr<ambr::store::StoreManager>  store_manager);
  void StopRpcServer();
  void RpcThreadFunc();
private:
  std::thread* rpc_thread_;
  std::shared_ptr<ambr::store::StoreManager>  store_manager_;
  std::unique_ptr<grpc::Server> rpc_server_;
};
}
}
#endif
