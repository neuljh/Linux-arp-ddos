#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "thread_get_config.h"
#include"thread_exe_attack.h"
#include"thread_scan.h"
#include"thread_ddos_attack.h"



#include <QMainWindow>
#include<QScrollBar>
#include<QTableWidgetItem>
#include<QMessageBox>
#include<QDateTime>
#include<QTimer>

#include<vector>
#include<iostream>
#include<string>
using namespace std;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButton_3_clicked();

    void on_pb_default_clicked();

    void on_pb_reset_clicked();

    void on_pb_clear_clicked();

    void on_cb_help_stateChanged(int arg1);

    void on_pushButton_clicked();

    void on_default_config_clicked();

    void setTableWidget(QTableWidget* table,vector<string> &header,int row,int column);          /* QTableWidget的初始化 */

    void on_arp_table_itemClicked(QTableWidgetItem *item);

    void on_exe_attack_clicked();

    void on_stop_attack_clicked();

    void set_log(string log);

    void set_ddos_log(string log);

    void set_packet_data(string data);

    void on_clear_log_clicked();

    void on_stop_get_packet_clicked();

    void on_ddos_default_config_clicked();

    void on_ddos_exe_attack_clicked();

    void on_ddos_stop_attack_clicked();

    void on_ddos_clear_log_clicked();

    void on_all_data_clear_clicked();

    void update_data_all();

    void on_pushButton_2_clicked();

    void on_btn_next_clicked();

signals:
    void send_attack_ip_mac(const vector<string> &ip_mac);
    void send_data_to_ddos(const vector<string> &data);

private:
    Ui::MainWindow *ui;
    Thread_get_config* thread_get_config;
    Thread_exe_attack* thread_exe_attack;
    Thread_scan* thread_scan;
    Thread_ddos_attack* thread_ddos_attack;
};

#endif // MAINWINDOW_H
