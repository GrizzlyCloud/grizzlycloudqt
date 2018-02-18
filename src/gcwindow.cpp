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
#include <QDebug>
#include <QCoreApplication>
#include <QDataStream>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

#include "grizzlycloud.h"

#include "gcwindow.h"

GCWindow::GCWindow(QStringList &args)
{
    QString err;

    timerDisconnected = NULL;
    activeTunnels.clear();
    listPairs.clear();

    if(parse(parsed, args, err) != GCCLI_OK) {
        QString msg = QString("Config: %1").arg(err);
        qDebug() << msg;
        exit(1);
    }

    QStringList config = getParsedValue(parsed, PCONFIG);
    QStringList logf   = getParsedValue(parsed, PLOG);

    if(config.length() != 1 || logf.length() != 1) {
        qDebug() << "Config: please specify --log <file> and --config <file>";
        exit(1);
    }

    logFile    = logf[0];

    if(considerConfigFile(config[0]) != 0) {
        exit(1);
    }

    gc = new GrizzlyCloud(this);

    connect(gc, SIGNAL(gc_signal_SocketStateChanged(QAbstractSocket::SocketState)),
            this, SLOT(socketStateChanged(QAbstractSocket::SocketState)));

    connect(gc, SIGNAL(gc_signal_SocketError(QAbstractSocket::SocketError)),
            this, SLOT(socketError(QAbstractSocket::SocketError)));

    connect(gc, SIGNAL(gc_signal_Login(QString,QString,QString)),
            this, SLOT(callbackLogin(QString,QString,QString)));

    connect(gc, SIGNAL(gc_signal_PairDevice(QString,QString,QByteArray,QByteArray,QByteArray,QByteArray,QString)),
            this, SLOT(callbackPairDevice(QString,QString,QByteArray,QByteArray,QByteArray,QByteArray,QString)));

    connect(gc, SIGNAL(gc_signal_UpdatedTraffic(QString,QString,QString,QString,QString,QString,QString)),
            this, SLOT(callbackUpdatedTraffic(QString,QString,QString,QString,QString,QString,QString)));

    connect(gc, SIGNAL(gc_signal_TunnelDenied(QString,QString,QString)),
            this, SLOT(callbackTunnelDenied(QString,QString,QString)));

    connect(gc, SIGNAL(gc_signal_TunnelDeniedDefender(QString,QString,QString)),
            this, SLOT(callbackTunnelDeniedDefender(QString,QString,QString)));

    connect(gc, SIGNAL(gc_signal_DeviceOffline(QString,QString,QByteArray)),
            this, SLOT(callbackDeviceOffline(QString,QString,QByteArray)));

    connect(gc, SIGNAL(gc_signal_TrafficGet(QList<TrafficList>,QString)),
            this, SLOT(callbackTrafficGet(QList<TrafficList>,QString)));

    connect(gc, SIGNAL(gc_signal_AccountSet(QByteArray)),
            this, SLOT(callbackAccountSet(QByteArray)));

    connect(gc, SIGNAL(gc_signal_AccountList(QStringList)),
            this, SLOT(callbackAccountList(QStringList)));

    connect(gc, SIGNAL(gc_signal_ClientStateChanged(QByteArray,QByteArray,quint16,QAbstractSocket::SocketState)),
            this, SLOT(callbackClientStateChanged(QByteArray,QByteArray,quint16,QAbstractSocket::SocketState)));

    connect(gc, SIGNAL(gc_signal_VersionMismatch(QByteArray,QByteArray)),
            this, SLOT(callbackVersionMismatch(QByteArray,QByteArray)));

    connect(gc, SIGNAL(gc_signal_AccountExists(QByteArray)),
            this, SLOT(callbackAccountExists(QByteArray)));

    connect(gc, SIGNAL(gc_signal_TunnelRemove(QString)),
            this, SLOT(callbackTunnelRemove(QString)));

    cloudConnect();

    // timer
    pairing = new QTimer(this);
    connect(pairing, SIGNAL(timeout()), this, SLOT(execTimerPairs()));
    pairing->start(5000);
}

GCWindow::~GCWindow()
{
    delete gc;
    delete pairing;
}

void GCWindow::cloudConnect()
{
    if(gc->availableHost(ip, host) != GC_OK) {
        QString msg = QString("Connect: No suitable host found");
        log(msg, L_ERROR);
        return;
    }
    gc->commandStartSession(ip, GC_CLOUD_PORT);
}

QStringList GCWindow::getParsedValue(QList<Parse> &parsed, enum parse_e type)
{
    QStringList r;

    int i;
    for(i = 0; i < parsed.count(); i++) {
        if(parsed[i].flag == type) {
            return parsed[i].args;
        }
    }

    return r;
}

enum status_e GCWindow::parse(QList<Parse> &parsed, QStringList &args, QString &error)
{
    parsed << (Parse("--user",			PUSER));
    parsed << (Parse("--password",  	PPASS));
    parsed << (Parse("--device", 		PDEVICE));
    parsed << (Parse("--tunnels", 		PTUNNELS));
    parsed << (Parse("--allow", 		PALLOW));
    parsed << (Parse("--limitupload", 	PLMTUP));
    parsed << (Parse("--limitdownload", PLMTDL));
    parsed << (Parse("--action", 		PACTION));
    parsed << (Parse("--config", 		PCONFIG));
    parsed << (Parse("--log", 			PLOG));

    int i, j;
    enum parse_e target = PNONE;

    for(i = 0; i < args.count(); i++) {

        bool found = false;

        for(j = 0; j < parsed.count(); j++) {
            if(args[i] == parsed[j].expression) {
                target = parsed[j].flag;
                found = true;
                break;
            }
        }

        if(found) continue;

        if(target != PNONE) {
            for(j = 0; j < parsed.count(); j++) {
                if(parsed[j].flag == target) {
                    parsed[j].args.append(args[i]);
                    break;
                }
            }
        }
    }

    qint32 check = 0;
    for(j = 0; j < parsed.count(); j++) {

        if(parsed[j].args.length() <= 0) continue;

        switch(parsed[j].flag) {
            case PUSER:
                check |= CUSER;
            break;
            case PPASS:
                check |= CPASS;
            break;
            case PDEVICE:
                check |= CDEVICE;
            break;
            case PTUNNELS:
                check |= CTUNNELS;
            break;
            case PALLOW:
                check |= CALLOW;
            break;
            case PACTION:
                check |= CACTION;
            break;
            case PLMTUP:
                check |= CLMTUP;
            break;
            case PLMTDL:
                check |= CLMTDL;
            break;
            case PCONFIG:
                check |= CCONFIG;
            case PLOG:
                check |= CLOG;
            break;
            default:
                return GCCLI_ERR;
        }
    }

    if(!EQFLAG(check, (CCONFIG|CLOG))) {
        error += "Mandatory parameters missing, please specify config and log files";
        return GCCLI_ERR;
    }

    return GCCLI_OK;
}

int GCWindow::considerConfigFile(QString configFile)
{
    QFile file;
    file.setFileName(configFile);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QString msg = QString("Config: File '%1' couldn't be loaded").arg(configFile);
        log(msg, L_ERROR);
        return -1;
    }

    QByteArray content = file.readAll();
    if(content.length() == 0) {
        QString msg = QString("Config: File '%1' empty %2").arg(configFile, file.size());
        log(msg, L_ERROR);
        return -1;
    }

    QJsonDocument doc(QJsonDocument::fromJson(content));
    QJsonObject json = doc.object();

    if(json.length() == 0) {
        QString msg = QString("Config: Parsing config file failed '%1' %2").arg(QString(file.readAll()), configFile);
        log(msg, L_ERROR);
        return -1;
    }

    config.user 		= json["user"].toString();
    config.password 	= json["password"].toString();
    config.device 		= json["device"].toString();

    QJsonArray allow = json["allow"].toArray();

    for(QJsonArray::iterator i = allow.begin(); i != allow.end(); i++) {
        config.allowedPorts.push_back(QVariant(*i).toUInt());
    }

    QJsonArray tunnels = json["tunnels"].toArray();
    for(QJsonArray::iterator i = tunnels.begin(); i != tunnels.end(); i++) {
        config.tunnels.push_back((*i).toObject().toVariantMap());
    }

    config.limitDown 	= json["limitDownload"].toInt();
    config.limitUp 	    = json["limitUpload"].toInt();

    config.action		= json["action"].toString();

    if(config.action == QString("traffic_mi")) {
        return 0;
    }

    if(config.action == QString("account_exists") &&
       config.user.length() > 0 &&
       config.password.length() > 0) {
        return 0;
    }

    if(config.user.length() < 0 || config.password.length() < 0 || config.device.length() < 0) {
        QString msg = QString("Config: Device, user or password missing");
        log(msg, L_ERROR);
        return -1;
    }

    if(config.tunnels.length() < 0 && config.allowedPorts.length() < 0) {
        QString msg = QString("Config: tunnels or allow directive not defined");
        log(msg, L_ERROR);
        return -1;
    }

    return 0;
}

void GCWindow::socketStateChanged(QAbstractSocket::SocketState state)
{
    if(state == QAbstractSocket::ConnectedState) {
        QString msg = QString("Connected to %1.grizzlycloud.com").arg(host);
        log(msg, L_INFO);

        quint32 limit_dl 		  	 	   = 0;
        quint32 download   		 	   	   = config.limitDown;
        if(download > 0) limit_dl 		   = download;
        gc->setDownloadLimit(limit_dl);

        if(timerDisconnected) {
            timerDisconnected->stop();
            delete timerDisconnected;
            timerDisconnected = NULL;
        }

        if(config.action.length() > 0) {
            if(config.action == "account_create") accountCreate();
            else if(config.action == "traffic_get") login();
            else if(config.action == "traffic_mi") trafficMi();
            else if(config.action == "account_exists") accountExists();
        } else {
            login();
        }
    }
}

void GCWindow::socketError(QAbstractSocket::SocketError error)
{
    QString msg = QString("Socket: error '%1'").arg(error);
    log(msg, L_ERROR);

    if(timerDisconnected == NULL) {

        // clean up everything
        gc->commandStopSession();

        // delete listPairs
        deactivatePairs();

        // delete user's active tunnels
        activeTunnels.clear();

        // try to reconnect
        timerDisconnected = new QTimer(this);
        connect(timerDisconnected, SIGNAL(timeout()), this, SLOT(cloudConnect()));
        timerDisconnected->start(2000);
    }
}

void GCWindow::trafficMi()
{
    gc->commandTrafficMi();
}

void GCWindow::accountCreate()
{
    QString login = config.user;
    QString pass  = config.password;

    if(login.length() == 0 || pass.length() == 0) {
        QString msg = QString("Account create: login or password missing");
        log(msg, L_ERROR);
        exit(1);
    }

    gc->commandAccountCreate(login, pass);
}

void GCWindow::accountExists()
{
    QString login = config.user;
    QString pass  = config.password;

    if(login.length() == 0 || pass.length() == 0) {
        QString msg = QString("Account create: login or password missing");
        log(msg, L_ERROR);
        exit(1);
    }

    gc->commandAccountExists(login, pass);
}

void GCWindow::accountList()
{
    gc->commandAccountList();
}

void GCWindow::trafficGet()
{
    gc->commandTrafficGet();
}

void GCWindow::login()
{
    QString login = config.user;
    QString pass  = config.password;
    QString dev   = config.device;

    if(login.length() == 0 || pass.length() == 0 || dev.length() == 0) {
        QString msg = QString("Login: login, password or device missing");
        log(msg, L_ERROR);
        quit();
        return;
    }

    gc->commandLogin(login, pass, dev);
}

void GCWindow::allowPorts(QList<QVariant> allowed)
{
    int i;

    quint32 limit_up 	 			 = 0;
    quint32 upload		   			 = config.limitUp;
    if(upload > 0) limit_up 		 = upload;

    for(i = 0; i < allowed.count(); i++) {
        if(gc->commandAllowedAdd(QVariant(allowed[i]).toUInt(), limit_up) == GC_OK) {
            QString msg = QString("Allow port: allowed '%1'").arg(QVariant(allowed[i]).toString());
            log(msg, L_INFO);
        }
    }
}

void GCWindow::openTunnels(QList<QVariant> tunnels)
{
    for(QList<QVariant>::iterator i = tunnels.begin(); i != tunnels.end(); i++) {
        QMap<QString, QVariant> map = QVariant(*i).toMap();
        QString cloud     = QVariant(map.value("cloud")).toString();
        QString device    = QVariant(map.value("device")).toString();
        quint16	port	  = QVariant(map.value("port")).toUInt();
        quint16	portLocal = QVariant(map.value("portLocal")).toUInt();

        if(cloud.length() == 0 || device.length() == 0 ||
           port == 0 || portLocal == 0) {
            QString msg = QString("Tunnel: Ignoring tunnel, params number is incorrect. Must be 4");
            log(msg, L_WARN);
            continue;
        }

        addTimerPairs(cloud, device, port, portLocal);
    }
}

void GCWindow::callbackTrafficGet(QList<TrafficList> list, QString error)
{
    if(error == "ok" || error == "ok_partial") {
        QString msg = QString("Traffic: status [%1]").arg(error);
        log(msg, L_INFO);

        for(QList<TrafficList>::iterator l = list.begin(); l != list.end(); l++) {
            QString msg = QString("Traffic Cloud [%4] on device: [%1] Upload: %2 Download: %3 Type: [%5]").arg(
                                  QString(l->device), QString(l->upload), QString(l->download),
                                  QString(l->cloud), QString(l->type));
            log(msg, L_INFO);
        }
    } else {
        QString msg = QString("Traffic: error [%1]").arg(error);
        log(msg, L_ERROR);
    }

    quit();
}

void GCWindow::callbackAccountSet(QByteArray error)
{
    QString msg = QString("Account Set [%1]").arg(QString(error));
    log(msg, L_INFO);

    quit();
}

void GCWindow::callbackTunnelRemove(QString fd)
{
    QString msg = QString("Tunnel removed: [%1]").arg(fd);
    log(msg, L_INFO);
}

void GCWindow::callbackAccountExists(QByteArray error)
{
    QString msg = QString("Account exists [%1]").arg(QString(error));
    log(msg, L_INFO);

    quit();
}

void GCWindow::callbackVersionMismatch(QByteArray master, QByteArray slave)
{
    (void) master;
    (void) slave;
    QString msg = QString("Versions mismatch");
    log(msg, L_ERROR);

    quit();
}

void GCWindow::callbackClientStateChanged(QByteArray cloud, QByteArray device, quint16 port,
                                          QAbstractSocket::SocketState state)
{
    QMap<qint32, QString> m;
    m.insert(0, QString("UnconnectedState"));
    m.insert(1, QString("HostLookupState"));
    m.insert(2, QString("ConnectingState"));
    m.insert(3, QString("ConnectedState"));
    m.insert(4, QString("BoundState"));
    m.insert(5, QString("ListeningState"));
    m.insert(6, QString("ClosingState"));

    QString msg = QString("ClientStateChanged: [%1:%2:%3] %4").arg(QString(cloud), QString(device),
                                                                 QVariant(port).toString(), m.value(QVariant(state).toInt()));
    log(msg, L_INFO);
}

void GCWindow::callbackAccountList(QStringList list)
{
    for(QStringList::iterator i = list.begin(); i != list.end(); i++) {
        QString msg = QString("Account List [%1]").arg(*i);
        log(msg, L_INFO);
    }

    quit();
}

void GCWindow::quit()
{
    if(gc) gc->commandStopSession();
    QCoreApplication::quit();
}

void GCWindow::callbackDeviceOffline(QString cloud, QString device, QByteArray address)
{
    QString msg = QString("Device '%1' from Cloud '%2' went offline").arg(device, cloud);
    log(msg, L_INFO);

    QList<qintptr> values = activeTunnels.values(address);
    for(int j = 0; j < values.size(); ++j) {
        gc->commandTunnelStop(values.at(j));
        QString msg = QString("Stopping tunnel [%1]").arg(values.at(j));
        log(msg, L_INFO);
    }

    activeTunnels.remove(address);

    msg = QString("Active tunnels:");
    log(msg, L_INFO);

    QMap<QByteArray, qintptr>::const_iterator i;
    for(i = activeTunnels.begin(); i != activeTunnels.end(); i++) {
        QString msg = QString("ptr: '%1'").arg(i.value());
        log(msg, L_INFO);
    }

    deactivatePair(address);
}

void GCWindow::deactivatePairs()
{
    mListPairs.lock();

    for(QList<ListPairs>::iterator i = listPairs.begin(); i != listPairs.end(); i++) {
        i->active = false;
        i->deviceAddress = QByteArray("");
    }

    mListPairs.unlock();
}

void GCWindow::deactivatePair(QByteArray deviceAddress)
{
    // Restore all combinations of local/remote ports for cloud/device combination
    mListPairs.lock();

    for(QList<ListPairs>::iterator i = listPairs.begin(); i != listPairs.end(); i++) {
        if(i->deviceAddress == deviceAddress) {
            i->active = false;
            i->deviceAddress = QByteArray("");
        }
    }

    mListPairs.unlock();
}

void GCWindow::callbackLogin(QString cloud, QString device, QString error)
{
    if(error == "ok") {
        QString msg =  QString("Login: successful for device '%2' from cloud '%1'").arg(cloud, device);
        log(msg, L_INFO);

        QString action = config.action;
        if(action.length() > 0 && action == "traffic_get") {
            trafficGet();
        } else {
            // allowed ports
            QList<QVariant> allowed = config.allowedPorts;
            if(!allowed.isEmpty()) {
                allowPorts(allowed);
            }

            // tunnels
            QList<QVariant> tunnels = config.tunnels;
            if(!tunnels.isEmpty()) {
                openTunnels(tunnels);
            }
        }
    } else {
        QString msg = QString("Login: error");
        log(msg, L_ERROR);
        QCoreApplication::quit();
    }
}

void GCWindow::log(QString msg, enum log_e type)
{
    QString time = Utils::time();
    char buf[1024];
    QByteArray fmt;

    switch(type) {
        case L_INFO: {
            snprintf(buf, sizeof(buf), "\33[;35;34m %s INFO: %s\33[m\n", time.toLocal8Bit().data(), msg.toLocal8Bit().data());
        }
        break;
        case L_WARN:
            snprintf(buf, sizeof(buf), "\33[;;33m %s WARNING: %s\33[m\n", time.toLocal8Bit().data(), msg.toLocal8Bit().data());
        break;
        case L_ERROR:
            snprintf(buf, sizeof(buf), "\33[;;31m %s ERROR: %s\33[m\n", time.toLocal8Bit().data(), msg.toLocal8Bit().data());
        break;
        default:
            return;
        break;
    }

    fmt = QByteArray(buf, strlen(buf));
    QFile file(logFile);
    file.open(QIODevice::Text | QIODevice::Append);
    QTextStream out(&file);
    out << fmt;
    file.close();
}

void GCWindow::tunnelStart(QString cloud, QString device, QByteArray pid, quint16 localPort, quint16 remotePort)
{
    qintptr fd;
    quint32 limit_up 	 	= 0;
    quint32 upload   		= config.limitUp;
    if(upload > 0) limit_up = upload;

    if(gc->commandTunnelStart(cloud, device, pid,
                              remotePort,
                              localPort,
                              limit_up,
                              &fd) == GC_OK) {

        activeTunnels.insert(pid, fd);

        QString msg = QString("Tunnel: Successfully created for\n\tdevice: '%1'\n\tcloud: '%2'\n\tlocal port: '%3'\n\tremote port: '%4'").arg(
                              device,
                              cloud,
                              QString::number(remotePort),
                              QString::number(localPort));
        log(msg, L_INFO);
    } else {
        QString msg = QString("Tunnel: Cannot be created on local port %1").arg(QString::number(remotePort));
        log(msg, L_ERROR);
    }
}

void GCWindow::callbackTunnelDeniedDefender(QString cloud, QString device, QString port)
{
    QString msg = QString("Traffic denied: Cloud '%2' device '%3' tried to connect to local port '%1'").arg(port, cloud, device);
    log(msg, L_ERROR);
}

void GCWindow::callbackTunnelDenied(QString port, QString cloud, QString device)
{
    QString msg = QString("Traffic denied: Remote port '%1' not alloed on cloud '%2' device '%3'").arg(port, cloud, device);
    log(msg, L_ERROR);
}

void GCWindow::callbackUpdatedTraffic(QString cloud, QString device, QString localPort, QString remotePort,
                                      QString fd, QString down, QString up)
{
    if(down == QString("0") && up == QString("0")) return;

    QString msg = QString("Traffic: [%4:%5:%6] remote [%7] fd [%3]: Down [%1] Up [%2]"
                          ).arg(down, up, fd, cloud, device, localPort, remotePort);
    log(msg, L_INFO);
}

void GCWindow::callbackPairDevice(QString cloud, QString device, QByteArray pid, QByteArray remotePort,
                                  QByteArray localPort, QByteArray type, QString error)
{
    if(error == "ok" && cloud != "" && device != "" && pid.length() != 0) {

        activateTimerPairs(cloud, device, pid,
                           QVariant(remotePort).toUInt(), QVariant(localPort).toUInt());

        if(type == "requested") {
            QString msg = QString("Pair Device: device '%1' from cloud '%2' paired on local '%3' remote '%4' ports"
                                  ).arg(device, cloud, localPort, remotePort);
            log(msg, L_INFO);

            tunnelStart(cloud, device, pid, QVariant(remotePort).toUInt(), QVariant(localPort).toUInt());
        } else {
            QString msg = QString("Pair Device: Request approved from [%2:%1:%4] to pair local port '%3'"
                                  ).arg(device, cloud, remotePort, localPort);
            log(msg, L_INFO);
        }
    } else {
        QString msg = QString("Pair Device: combination of cloud and device not found (might be offline)");
        log(msg, L_ERROR);
    }
}

void GCWindow::addTimerPairs(QString cloud, QString device, quint16 localPort, quint16 remotePort)
{
    if(!(cloud.length() > 0 && device.length() > 0)) return;

    mListPairs.lock();

    // Skip entry if exists
    for(QList<ListPairs>::iterator i = listPairs.begin(); i != listPairs.end(); i++) {
        if(i->cloud == cloud && i->device == device &&
           i->localPort == localPort && i->remotePort == remotePort) {
            mListPairs.unlock();
            QString msg = QString("Pair Device: Device '%1' from cloud '%2' on ports '%3%4' already exists"
                                  ).arg(device, cloud,
                                        QString::number(localPort), QString::number(remotePort));
            log(msg, L_WARN);
            return;
        }
    }

    ListPairs lp;
    lp.cloud 		= cloud;
    lp.device 		= device;
    lp.localPort 	= localPort;
    lp.remotePort	= remotePort;
    lp.active		= false;
    listPairs.push_back(lp);

    mListPairs.unlock();

    QString msg = QString("Pair Device: Added pair cloud: '%1' device: '%2' local '%3' remote '%4' ports"
                          ).arg(cloud, device, QString::number(localPort), QString::number(remotePort));
    log(msg, L_INFO);
}

void GCWindow::activateTimerPairs(QString cloud, QString device, QByteArray deviceAddress,
                                  quint16 localPort, quint16 remotePort)
{
    mListPairs.lock();
    for(QList<ListPairs>::iterator i = listPairs.begin(); i != listPairs.end(); i++) {
        if(i->cloud == cloud && i->device == device &&
           i->localPort == localPort && i->remotePort == remotePort) {

            QString msg = QString("TimerPair: Pair '%1' '%2' activated").arg(i->cloud, i->device);
            log(msg, L_INFO);
            i->active = true;
            i->deviceAddress = deviceAddress;
            break;
        }
    }
    mListPairs.unlock();
}

void GCWindow::execTimerPairs()
{
    mListPairs.lock();
    for(QList<ListPairs>::iterator i = listPairs.begin(); i != listPairs.end(); i++) {
        if(i->active == true) {
            continue;
        }

        if(gc->commandPairDevice(i->cloud, i->device, i->localPort, i->remotePort) != GC_REGISTERED) {
            QString msg = QString("TimerPair: Couldn't pair '%1' '%2' ports %3/%4"
                                  ).arg(i->cloud, i->device,
                                        QString::number(i->localPort), QString::number(i->remotePort));
            log(msg, L_ERROR);
        } else {
            QString msg = QString("TimerPair: Request sent to pair '%1' '%2' ports %3/%4"
                                  ).arg(i->cloud, i->device,
                                        QString::number(i->localPort), QString::number(i->remotePort));
            log(msg, L_INFO);
        }
    }
    mListPairs.unlock();
}
