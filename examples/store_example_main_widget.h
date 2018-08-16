#ifndef STORE_EXAMPLE_MAIN_WIDGET_H
#define STORE_EXAMPLE_MAIN_WIDGET_H

#include <memory>
#include <unordered_map>
#include <QWidget>
#include <QMap>
#include <QTimer>

#include <core/key.h>
#include <core/unit.h>

#include "net.h"
#include "net_test.h"
#include "utils/validator_auto.h"
#include "synchronization/syn_manager.h"

namespace Ui {
  class StoreExampleMainWidget;
}
namespace ambr {
namespace store{
  class UnitStore;
  class StoreManager;
}
}
class StoreExampleMainWidget : public QWidget
{
  Q_OBJECT
  struct DrawItem{
    QPoint space_;
    std::shared_ptr<ambr::store::UnitStore> unit_store_;
    std::shared_ptr<ambr::core::ValidatorUnit> validator_unit_store_;
  };
public:
  explicit StoreExampleMainWidget(std::shared_ptr<ambr::store::StoreManager> store_manager,std::shared_ptr<ambr::syn::SynManager> syn_manager, QWidget *parent = 0);
  ~StoreExampleMainWidget();
signals:
  void sgAccept(CNode*);
  void sgConnect(CNode*);
  void sgDisconnected(CNode*);
  void DoConnect(std::shared_ptr<ambr::net::Peer> peer);
  void DoAccept(std::shared_ptr<ambr::net::Peer> peer);
  void DoDisconnected(std::shared_ptr<ambr::net::Peer> peer);
private slots:
  void on_btnPTRepaint_clicked();
  void on_btnTranslateReceive_clicked();
  void on_btnTranslateSend_clicked();
  void on_radioButton_9_clicked();
  void on_radioButton_10_clicked();
  void on_radioButton_12_clicked();
  void on_radioButton_11_clicked();
  void on_btnTranslateHistory_clicked();
  void on_btnUnReceived_clicked();
  void on_btnAccountList_clicked();
  void on_btnAccountBalance_clicked();
  void on_btnPubKey2Addr_clicked();
  void on_btnPriKey2PubKey_clicked();
  void on_cmbTestPrivateKey_currentTextChanged(const QString &arg1);
  void on_btnUnit_clicked();
  void on_btnPTLength_clicked();
  void on_btnP2PStart_clicked();
  void on_btnInitDataBase_clicked();
  void on_btnPVRemoveVote_clicked();
  void on_btnPVTime_clicked();
  void on_btnPVAddVote_clicked();
  void on_btnPVRemoveCheck_clicked();
  void on_btnPVAddCheck_clicked();
  void on_pushButton_clicked();
  void on_btnPVValidatorUnit_clicked();
  void on_btnTranslateUnfreeze_clicked();
  void on_btnTranslateCashDisposite_clicked();
  void on_btnAccountNew_clicked();
  void on_btnFlushValidatorSet_clicked();
  void on_btnAddSV_clicked();
  void on_btnVote_clicked();
  void on_btnFlushVote_clicked();
  void on_btnMSVStart_1_clicked();
  void on_btnMSVStop_1_clicked();
  void on_btnMSVStart_2_clicked();
  void on_btnMSVStop_2_clicked();
  void on_btnMSVStart_3_clicked();
  void on_btnMSVStop_3_clicked();
  void on_btnMSVStart_4_clicked();
  void on_btnMSVStop_4_clicked();
  void on_btnMSVStart_5_clicked();
  void on_btnMSVStop_5_clicked();
  void on_btnMSVStart_6_clicked();
  void on_btnMSVStop_6_clicked();

  void on_btnMSVStartTrans_1_clicked();
  void on_btnMSVStartTrans_2_clicked();
  void on_btnMSVStartTrans_3_clicked();
  void on_btnMSVStartTrans_4_clicked();
  void on_btnMSVStartTrans_5_clicked();
  void on_btnMSVStartTrans_6_clicked();
  void on_btnMSVStopTrans_1_clicked();
  void on_btnMSVStopTrans_2_clicked();
  void on_btnMSVStopTrans_3_clicked();
  void on_btnMSVStopTrans_4_clicked();
  void on_btnMSVStopTrans_5_clicked();
  void on_btnMSVStopTrans_6_clicked();

  void onDealAccept(CNode*);
  void onDealConnect(CNode*);
  void onDealDisconnected(CNode*);
  void DealConnect(std::shared_ptr<ambr::net::Peer> peer);
  void DealAccept(std::shared_ptr<ambr::net::Peer> peer);
  void DealDisconnected(std::shared_ptr<ambr::net::Peer> peer);
  void OnDrawTimerOut();
protected:
  bool eventFilter(QObject *target, QEvent *event);


private:
  Ui::StoreExampleMainWidget *ui;
  QStringList test_pri_key_list_;
  QString root_pri_key_;
private://For paint
  void DrawChain();
  void DrawUnit(QPainter& pt);
  void DrawLines(QPainter& pt);
  void DrawLine(QPainter &pt, const QPoint& from, const QPoint& to, bool b_arrow);
  bool OnMouseMove(QEvent* event);
  bool OnMousePress(QEvent* event);
private:
  void OnAcceptNode(CNode* p_node);
  void OnConnectNode(CNode* p_node);
  void OnDisconnectedNode(CNode* p_node);
  void OnConnect(std::shared_ptr<ambr::net::Peer> peer);
  void OnAccept(std::shared_ptr<ambr::net::Peer> peer);
  void OnDisconnected(std::shared_ptr<ambr::net::Peer> peer);
private:
  //check ValidatorUnit
  void CheckValidatorUnit();
  void CreateDebugInitChain();
private:
  QTimer chain_draw_timer;
  uint32_t max_chain_length_for_draw_;
  std::unordered_map<ambr::core::UnitHash, std::list<std::shared_ptr<DrawItem>>> unit_list_;
  std::unordered_map<ambr::core::UnitHash, std::shared_ptr<DrawItem>> unit_map_;
  ambr::core::UnitHash active_unit_;
  ambr::core::UnitHash selected_unit_;
private:
  std::shared_ptr<ambr::syn::SynManager> p_syn_manager;
  std::shared_ptr<ambr::store::StoreManager> store_manager_;
  std::vector<std::shared_ptr<ambr::utils::ValidatorAuto>> validator_auto_;
private:
  void StartPublishTrans(const ambr::core::PrivateKey& pri_key);
  void AutoPublishTransThread(const ambr::core::PrivateKey& pri_key);
  void StopPublishTrans(const ambr::core::PrivateKey& pri_key);
  std::unordered_map<ambr::core::PrivateKey, std::pair<bool, std::shared_ptr<std::thread>>> auto_publish_trans_thread_map_;
};

#endif // STORE_EXAMPLE_MAIN_WIDGET_H
