#!/bin/bash

pidfile=/tmp/rprototestssocatpids
PORT1=/tmp/rproto1
PORT2=/tmp/rproto2

exitcode=1

case $1 in
start)
    socat pty,link=$PORT1,raw,echo=0 pty,link=$PORT2,raw,echo=0 > /dev/null 2>&1 &
    socatpid=$!
    if [[ $(ps -p $! -o comm=) == socat ]]; then
        echo $socatpid >> $pidfile
        count=0
        until [[ -e $PORT1 || -e $PORT2 ]]
        do
            if (( $count > 100 )); then
                echo "Failed to create virtual ports"
                exit 1
            fi
            count=$(($count +1))
            sleep 0.001
        done
        echo "Virtal ports created: '$PORT1', '$PORT2'"
        exitcode=0
    else
        echo "ERROR: pid '$socatpid' not socat"
    fi
    ;;
stop)
    if [[ -e "$pidfile" ]]; then
        while IFS= read -r pid; do
            echo killing $pid
            kill $pid
        done < "$pidfile"
        rm $pidfile
    fi
    exitcode=0
    ;;
esac
exit $exitcode
