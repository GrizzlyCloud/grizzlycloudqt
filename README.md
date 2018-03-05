# GrizzlyCloud QT client

GrizzlyCloud is a simplified VPN alternative for IoT (Internet of Things). Essentially it's just a client-server architecture that forwards your local TCP port requests to appropriate recipient. GrizzlyCloud QT client aims to provide a cross-platform support for those who find it suitable. For everyone there is a client library in [C language](https://github.com/GrizzlyCloud/grizzlycloudlib).

# Requirements

GrizzlyCloud QT client was developed using QT5 framework (5.10.0). It was not tested under any other QT version.
[GrizzlyCloud QT library](https://github.com/GrizzlyCloud/grizzlycloudlibqt) is essential.

# Guide

Start client as:
```sh
grizzlycloud --config <config_file> --log <log_file>
```

or execute script/grizzlycloudctl.sh file.

Find out more about format of config file and available commands at [Wiki pages](https://grizzlycloud.com/wiki/doku.php?id=commands).

# Disclaimer

This version of client is abandonware and it's only present becase of somebody who's interested in QT implementation. You should use [C version](https://github.com/GrizzlyCloud/grizzlycloudlib) instead.
