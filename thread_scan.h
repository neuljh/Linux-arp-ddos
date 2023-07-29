#ifndef THREAD_SCAN_H
#define THREAD_SCAN_H


#include <qthread.h>
#include<QDateTime>
#include<vector>
#include<iostream>
#include<string>
using namespace std;

class Thread_scan : public QThread
{
public:
    void run();
    Thread_scan(QObject* parent);
    ~Thread_scan();
signals:

public slots:

};

#endif // THREAD_SCAN_H
