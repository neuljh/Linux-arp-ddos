#ifndef THREAD_EXE_ATTACK_H
#define THREAD_EXE_ATTACK_H


#include <qthread.h>
#include<QDateTime>
#include<vector>
#include<iostream>
#include<string>
using namespace std;
class Thread_exe_attack : public QThread
{
public:
    void recv_ip_mac(const vector<string> &ip_mac_temp);
    void run();
    Thread_exe_attack(QObject* parent);
    ~Thread_exe_attack();
signals:

public slots:
private:
    vector<string> ip_mac;
};

#endif // THREAD_EXE_ATTACK_H
