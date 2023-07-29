#-------------------------------------------------
#
# Project created by QtCreator 2022-12-21T12:22:52
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Internet_safty
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        main.cpp \
        mainwindow.cpp \
    core.cpp \
    arp_attack.cpp \
    thread_get_config.cpp \
    thread_exe_attack.cpp \
    thread_scan.cpp \
    ddos_attack.cpp \
    thread_ddos_attack.cpp \
    data_all.cpp \
    libpcap9.cpp

HEADERS += \
        mainwindow.h \
    core.h \
    arp_attack.h \
    thread_get_config.h \
    thread_exe_attack.h \
    thread_scan.h \
    ddos_attack.h \
    thread_ddos_attack.h \
    data_all.h \
    dialog_all.h \
    libpcap9.h

FORMS += \
        mainwindow.ui

LIBS += -lpcap

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    imgs/header(visible).jpeg

RESOURCES +=
