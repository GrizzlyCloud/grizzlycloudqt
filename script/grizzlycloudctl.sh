#!/bin/bash

BIN=grizzlycloud

start() {
    if [ "$#" -ne 2 ]; then
        echo "error: start <config_file> <log_file>"
        exit 1
    fi

    echo "Starting GrizzlyCloud with config '$1' and log '$2'";
    nohup $BIN --config $1 --log $2 &
}

stop() {
    echo "Stopping GrizzlyCloud"
    killall -9 $BIN
}

case "$1" in
    start)
        start $2 $3
    ;;
    stop)
        stop
    ;;
    restart)
        stop
        start $2 $3
    ;;
    *)
        echo "Usage: {start|stop|restart}"
        exit
esac
