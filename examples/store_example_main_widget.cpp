#include "store_example_main_widget.h"
#include "ui_store_example_main_widget.h"

StoreExampleMainWidget::StoreExampleMainWidget(QWidget *parent) :
  QWidget(parent),
  ui(new Ui::StoreExampleMainWidget)
{
  ui->setupUi(this);
}

StoreExampleMainWidget::~StoreExampleMainWidget()
{
  delete ui;
}
