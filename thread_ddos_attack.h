#ifndef THREAD_DDOS_ATTACK_H
#define THREAD_DDOS_ATTACK_H

#include <qthread.h>
#include<QDateTime>
#include<vector>
#include<iostream>
#include<string>
using namespace std;
class Thread_ddos_attack : public QThread
{
public:
    void run();
    Thread_ddos_attack(QObject* parent);
    ~Thread_ddos_attack();
signals:

public slots:
    void recv_data_from_main(const vector<string> &data_temp);
private:
    vector<string> data;
};

#endif // THREAD_DDOS_ATTACK_H
