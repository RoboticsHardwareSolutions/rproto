#!/bin/bash

pidfile=/tmp/rprototestssocatpids
PORT1="/tmp/rproto1"
PORT2="/tmp/rproto2"

# Performance test ports
PERF_PORT1_TX="/tmp/perf_emu1_tx"
PERF_PORT1_RX="/tmp/perf_emu1_rx"
PERF_PORT2_TX="/tmp/perf_emu2_tx"
PERF_PORT2_RX="/tmp/perf_emu2_rx"
PERF_PORT3_TX="/tmp/perf_emu3_tx"
PERF_PORT3_RX="/tmp/perf_emu3_rx"

exitcode=1

cleanup() {
    if [[ -e "$pidfile" ]]; then
        while IFS= read -r p; do
            echo "killing $p"
            kill "$p" 2>/dev/null || true
        done < "$pidfile"
        rm -f "$pidfile"
    fi
    
    # Remove any leftover symlinks
    rm -f "$PORT1" "$PORT2"
    rm -f "$PERF_PORT1_TX" "$PERF_PORT1_RX"
    rm -f "$PERF_PORT2_TX" "$PERF_PORT2_RX"
    rm -f "$PERF_PORT3_TX" "$PERF_PORT3_RX"
}

start_port_pair() {
    local port_tx=$1
    local port_rx=$2
    
    socat pty,link="$port_tx",raw,echo=0 pty,link="$port_rx",raw,echo=0 > /dev/null 2>&1 &
    local socatpid=$!
    
    if [[ $(ps -p "$socatpid" -o comm= 2>/dev/null) != "socat" ]]; then
        echo "ERROR: pid '$socatpid' is not socat"
        return 1
    fi
    
    echo "$socatpid" >> "$pidfile"
    
    # Wait for both ports to be created
    local count=0
    while [[ ! -e "$port_tx" ]] || [[ ! -e "$port_rx" ]]; do
        if (( count > 100 )); then
            echo "Failed to create ports: $port_tx, $port_rx"
            return 1
        fi
        count=$((count + 1))
        sleep 0.01
    done
    
    echo "Ports created: '$port_tx', '$port_rx'"
    return 0
}

case $1 in
start)
    # Clean up any existing ports first
    cleanup
    
    # Standard rproto test ports
    if ! start_port_pair "$PORT1" "$PORT2"; then
        cleanup
        exit 1
    fi

    # Performance test ports (3 pairs)
    if ! start_port_pair "$PERF_PORT1_TX" "$PERF_PORT1_RX"; then
        cleanup
        exit 1
    fi
    
    if ! start_port_pair "$PERF_PORT2_TX" "$PERF_PORT2_RX"; then
        cleanup
        exit 1
    fi
    
    if ! start_port_pair "$PERF_PORT3_TX" "$PERF_PORT3_RX"; then
        cleanup
        exit 1
    fi
    
    exitcode=0
    ;;
stop)
    cleanup
    exitcode=0
    ;;
*)
    echo "Usage: $0 {start|stop}"
    exit 1
    ;;
esac

exit $exitcode
