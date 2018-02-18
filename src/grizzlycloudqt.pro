QT += core network
QT -= gui
#QMAKE_CXXFLAGS += -DNO_TLS

TARGET = grizzlycloudqt
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

DEPENDPATH += . ../../
INCLUDEPATH += ../../grizzlycloudlibqt/src
LIBS += -L../../grizzlycloudlibqt/src/ -lgrizzlycloudqt

SOURCES += main.cpp \
    gcwindow.cpp

HEADERS += \
    gcwindow.h

