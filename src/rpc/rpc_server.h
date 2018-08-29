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
  virtual ::grpc::Status GetMessageStream(::grpc::ServerContext* context, const ::ambr::rpc::MessageStreamRequest* request, ::grpc::ServerWriter< ::ambr::rpc::MessageStreamReply>* writer) override;
  virtual ::grpc::Status GetLastUnitHash(::grpc::ServerContext* context, const ::ambr::rpc::GetLastUnitHashRequest* request, ::ambr::rpc::GetLastUnitHashReplay* response) override;

  virtual ::grpc::Status PubSendTransf(::grpc::ServerContext* context, const ::ambr::rpc::PubSendTransfRequest* request, ::ambr::rpc::PubSendTransfReply* response) override;
  virtual ::grpc::Status PubReceiveTransf(::grpc::ServerContext* context, const ::ambr::rpc::PubReceiveTransfRequest* request, ::ambr::rpc::PubReceiveTransfReply* response) override;
  virtual ::grpc::Status PubSendMessage(::grpc::ServerContext* context, const ::ambr::rpc::PubSendMessageRequest* request, ::ambr::rpc::PubSendMessageReply* response) override;
public:
  RpcServer();
  ~RpcServer();
  bool StartRpcServer(std::shared_ptr<ambr::store::StoreManager>  store_manager);
  void StopRpcServer();
  void RpcThreadFunc();
private:
  bool GetMessage(MessageStreamReply& reply);
  void AddMessage(const MessageStreamReply& reply);
private:
  std::thread* rpc_thread_;
  std::shared_ptr<ambr::store::StoreManager>  store_manager_;
  std::unique_ptr<grpc::Server> rpc_server_;
};
}
}
#endif
