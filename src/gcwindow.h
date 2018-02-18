/*
 *
 * GrizzlyCloud QT - simplified VPN for IoT
 * Copyright (C) 2016 - 2017 Filip Pancik
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef GCWINDOW_H
#define GCWINDOW_H

#include <QTcpSocket>
#include <QStringList>
#include <QTimer>
#include <QMutex>

#include "grizzlycloud.h"

#define EQFLAG(m_dst, m_src) ((m_dst & m_src) == m_src)

enum check_e {
    CUSER 		= 1 << 0,
    CPASS 		= 1 << 1,
    CDEVICE 	= 1 << 2,
    CTUNNELS 	= 1 << 3,
    CALLOW 		= 1 << 4,
    CACTION 	= 1 << 5,
    CLMTUP 		= 1 << 6,
    CLMTDL 		= 1 << 7,
    CCONFIG		= 1 << 8,
    CLOG		= 1 << 9,
};

enum parse_e {
    PNONE		= 0,
    PUSER,
    PPASS,
    PDEVICE,
    PTUNNELS,
    PALLOW,
    PACTION,
    PLMTUP,
    PLMTDL,
    PCONFIG,
    PLOG
};

enum status_e {
    GCCLI_OK = 0,
    GCCLI_ERR,
};

enum log_e {
    L_INFO = 0,
    L_WARN,
    L_ERROR
};

class ListPairs {
public:
    QString cloud;
    QString device;
    quint16 localPort;
    quint16 remotePort;
    QByteArray deviceAddress;
    bool active;
};

class Config
{
public:
    QString user;
    QString password;
    QString device;

    QList<QVariant> tunnels;
    QList<QVariant> allowedPorts;

    quint32 limitUp;
    quint32 limitDown;

    QString action;
};

class Parse
{
public:
    Parse(QString expression, enum parse_e flag) :
        expression(expression), flag(flag) {}

    QString expression;
    QStringList args;
    enum parse_e flag;
};

class GCWindow : QObject
{
    Q_OBJECT
public:
    GCWindow(QStringList &args);
    virtual ~GCWindow();

private:
    enum status_e parse(QList<Parse> &parsed, QStringList &args, QString &error);
    QStringList getParsedValue(QList<Parse> &parsed, enum parse_e type);

private slots:
    void socketStateChanged(QAbstractSocket::SocketState state);
    void socketError(QAbstractSocket::SocketError);

    void callbackLogin(QString error, QString cloud, QString device);
    void callbackPairDevice(QString cloud, QString device, QByteArray pid, QByteArray localPort,
                            QByteArray remotePort, QByteArray type, QString error);
    void callbackUpdatedTraffic(QString cloud, QString device, QString localPort, QString remotePort, QString fd, QString down, QString up);
    void callbackTunnelDenied(QString port, QString cloud, QString device);
    void callbackTunnelDeniedDefender(QString cloud, QString device, QString port);
    void callbackDeviceOffline(QString cloud, QString device, QByteArray address);
    void callbackTrafficGet(QList<TrafficList> list, QString error);
    void callbackAccountSet(QByteArray error);
    void callbackAccountList(QStringList list);

    void cloudConnect();

    void execTimerPairs();

    void callbackClientStateChanged(QByteArray cloud, QByteArray device, quint16 port,
                                    QAbstractSocket::SocketState state);
    void callbackVersionMismatch(QByteArray master, QByteArray slave);

    void callbackAccountExists(QByteArray error);

    void callbackTunnelRemove(QString fd);
private:
    void login();
    void accountCreate();
    void accountList();
    void trafficGet();
    int considerConfigFile(QString configFile);
    void trafficMi();
    void accountExists();

    void allowPorts(QList<QVariant> allowed);
    void openTunnels(QList<QVariant> tunnels);
    void tunnelStart(QString cloud, QString device, QByteArray pid, quint16 localPort, quint16 remotPort);
    QStringList getPorts(QString cloud, QString device);

    void log(QString msg, enum log_e type);

    void addTimerPairs(QString cloud, QString device, quint16 localPort, quint16 remotePort);

    void quit();

    void activateTimerPairs(QString cloud, QString device, QByteArray deviceAddress,
                            quint16 localPort, quint16 remotePort);
    void deactivatePair(QByteArray deviceAddress);

    void deactivatePairs();
private:
    Config config;

    QList<Parse> parsed;

    QString logFile;

    GrizzlyCloud *gc;

    QString ip, host;

    QTimer *timerDisconnected;

    QMultiMap<QByteArray, qintptr> activeTunnels;

    QMutex mListPairs;

    QTimer *pairing;

    QList<ListPairs> listPairs;
};

#endif // GCWINDOW_H
