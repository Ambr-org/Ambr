#ifndef STORE_EXAMPLE_MAIN_WIDGET_H
#define STORE_EXAMPLE_MAIN_WIDGET_H

#include <memory>
#include <unordered_map>
#include <QWidget>
#include <QMap>
#include <core/key.h>
#include "net_test.h"
namespace Ui {
  class StoreExampleMainWidget;
}
namespace ambr {
namespace store{
  class UnitStore;
}
}
class StoreExampleMainWidget : public QWidget
{
  Q_OBJECT
  struct DrawItem{
    QPoint space_;
    std::shared_ptr<ambr::store::UnitStore> unit_store_;
  };
public:
  explicit StoreExampleMainWidget(QWidget *parent = 0);
  ~StoreExampleMainWidget();
signals:
  void DoConnect(std::shared_ptr<ambr::net::Peer> peer);
  void DoAccept(std::shared_ptr<ambr::net::Peer> peer);
  void DoDisconnected(std::shared_ptr<ambr::net::Peer> peer);
private slots:
  void on_btnPTRepaint_clicked();
  void on_btnTranslateReceive_clicked();
  void on_btnTranslateSend_clicked();
  void on_radioButton_9_clicked();
  void on_radioButton_10_clicked();
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

  void DealConnect(std::shared_ptr<ambr::net::Peer> peer);
  void DealAccept(std::shared_ptr<ambr::net::Peer> peer);
  void DealDisconnected(std::shared_ptr<ambr::net::Peer> peer);
protected:
  bool eventFilter(QObject *target, QEvent *event);

private:
  Ui::StoreExampleMainWidget *ui;
  QStringList test_pri_key_list_;
private://For paint
  void DrawChain();
  void DrawUnit(QPainter& pt);
  void DrawLines(QPainter& pt);
  void DrawLine(QPainter &pt, const QPoint& from, const QPoint& to, bool b_arrow);
  bool OnMouseMove(QEvent* event);
  bool OnMousePress(QEvent* event);
private:
  void OnConnect(std::shared_ptr<ambr::net::Peer> peer);
  void OnAccept(std::shared_ptr<ambr::net::Peer> peer);
  void OnDisconnected(std::shared_ptr<ambr::net::Peer> peer);
private:
  uint32_t max_chain_length_for_draw_;
  std::unordered_map<ambr::core::UnitHash, std::list<std::shared_ptr<DrawItem>>> unit_list_;
  std::unordered_map<ambr::core::UnitHash, std::shared_ptr<DrawItem>> unit_map_;
  ambr::core::UnitHash active_unit_;
  ambr::core::UnitHash selected_unit_;
};

#endif // STORE_EXAMPLE_MAIN_WIDGET_H
