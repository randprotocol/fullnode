#!/usr/bin/env bash
# A throwaway single-validator RAND chain from built binaries, for the downstream integration
# tests (randscan, randbridge.org, randprotocol.org, zusd.money — `docs/howto.md` §7, "How do I
# run the downstream integration tests?"). It cuts a genesis with the faucet on, starts one validator on
# loopback, waits for its RPC to answer, and prints what a test needs as `key=value` lines:
#
#   RPC_URL=http://127.0.0.1:<port>
#   GENESIS=<dir>/genesis.json
#   PID=<pid>
#   DIR=<dir>
#
# Stop it with `scripts/dev-chain.sh --stop <dir>`; the directory is left for the caller to read
# (`node.log`) or delete. Stopping twice is fine: a directory whose node is gone says so, exit 0.
#
# Inputs, all optional:
#   RAND_NODE_BIN       the node binary (default target/release/rand-node)
#   RAND_CLI            the wallet binary, for the payout key (default target/release/rand)
#   DEV_CHAIN_DIR       where the keys, genesis, database and log go (default: a fresh mktemp dir)
#   DEV_CHAIN_ID        the chain id (default 7)
#   DEV_CHAIN_RPC_PORT  the RPC port (default: a free one)
#   DEV_CHAIN_FEES      the genesis `fees` flags to turn on, comma-separated from burn_base,
#                       subsidy_net_of_fees, burn_floor (`docs/fees.md` §1.3). subsidy_net_of_fees
#                       needs an aggregation section, which no node starts on today, so on a dev
#                       chain it is refused at genesis.
#   DEV_CHAIN_FRI_PROFILE        test (default; fast, insecure) or production
#   DEV_CHAIN_BLOCK_INTERVAL_MS  block spacing (default 1000)
#   DEV_CHAIN_GENESIS_ARGS       extra `rand-node genesis` flags, word-split (e.g. "--gas-price 100")
#   DEV_CHAIN_BINDING_DOMAIN     the genesis `binding_domain`: 1, or 0 for none (default: 1, except
#                                0 for chain ids 14–19)
#
# The chain is cut with `--binding-domain 1`, as every chain since 20 is: a wallet signs nothing
# for a chain id outside 14–19 without it (BIND-1, `docs/deploy.md`). On 14–19 the wallet signs the
# chain-id form (`binding_domain_for`), so there the default is no binding domain.
set -euo pipefail

die() {
    echo "dev-chain: $*" >&2
    exit 1
}

# `--stop <dir>`: end the node the directory's pid file names, politely first.
if [ "${1:-}" = "--stop" ]; then
    dir=${2:-}
    [ -n "$dir" ] || die "usage: $0 --stop <dir>"
    [ -d "$dir" ] || die "$dir is not a directory"
    if [ ! -f "$dir/node.pid" ]; then
        echo "not running (no $dir/node.pid)"
        exit 0
    fi
    pid=$(cat "$dir/node.pid")
    if kill -0 "$pid" 2>/dev/null; then
        # It may exit between the probe and the signal; that is a stop too.
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.2
        done
        if kill -0 "$pid" 2>/dev/null; then
            echo "dev-chain: pid $pid ignored SIGTERM for 10 s; sending SIGKILL" >&2
            kill -9 "$pid" 2>/dev/null || true
        fi
        echo "stopped pid $pid"
    else
        echo "pid $pid is not running"
    fi
    rm -f "$dir/node.pid"
    exit 0
fi
[ $# -eq 0 ] || die "usage: $0 [--stop <dir>] (configuration is by environment; see the header)"

RAND_NODE_BIN=${RAND_NODE_BIN:-target/release/rand-node}
RAND_CLI=${RAND_CLI:-target/release/rand}
DEV_CHAIN_ID=${DEV_CHAIN_ID:-7}
case "$DEV_CHAIN_ID" in "" | *[!0-9]*) die "DEV_CHAIN_ID must be a number, got $DEV_CHAIN_ID" ;; esac
case "${DEV_CHAIN_RPC_PORT-0}" in "" | *[!0-9]*) die "DEV_CHAIN_RPC_PORT must be a number, got $DEV_CHAIN_RPC_PORT" ;; esac
DEV_CHAIN_FRI_PROFILE=${DEV_CHAIN_FRI_PROFILE:-test}
DEV_CHAIN_BLOCK_INTERVAL_MS=${DEV_CHAIN_BLOCK_INTERVAL_MS:-1000}
if [ "$DEV_CHAIN_ID" -ge 14 ] && [ "$DEV_CHAIN_ID" -le 19 ]; then
    DEV_CHAIN_BINDING_DOMAIN=${DEV_CHAIN_BINDING_DOMAIN:-0}
else
    DEV_CHAIN_BINDING_DOMAIN=${DEV_CHAIN_BINDING_DOMAIN:-1}
fi
case "$DEV_CHAIN_BINDING_DOMAIN" in
    0) binding_args=() ;;
    1) binding_args=(--binding-domain 1) ;;
    *) die "DEV_CHAIN_BINDING_DOMAIN must be 0 or 1, got $DEV_CHAIN_BINDING_DOMAIN" ;;
esac
[ -x "$RAND_NODE_BIN" ] || die "RAND_NODE_BIN=$RAND_NODE_BIN is not an executable (build it, or download the release asset)"
[ -x "$RAND_CLI" ] || die "RAND_CLI=$RAND_CLI is not an executable (build it, or download the release asset)"
command -v python3 >/dev/null || die "python3 is needed to find a free port"
command -v curl >/dev/null || die "curl is needed to poll the RPC"

# Two ports the kernel says are free right now, distinct (both sockets are held while the second
# is asked for). The node binds them a moment later; the race is the same one every test harness
# takes, and the poll below fails loudly if it is lost.
free_ports() {
    python3 -c 'import socket
a, b = socket.socket(), socket.socket()
a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
print(a.getsockname()[1], b.getsockname()[1])
a.close(); b.close()'
}

DIR=${DEV_CHAIN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/rand-dev-chain.XXXXXX")}
mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)
[ ! -e "$DIR/genesis.json" ] || die "$DIR already holds a chain; pick an empty DEV_CHAIN_DIR"
read -r port_a port_b <<<"$(free_ports)"
RPC_PORT=${DEV_CHAIN_RPC_PORT:-$port_a}
# The second probe is never the first, so it is the P2P port unless the caller chose that number.
P2P_PORT=$port_b
[ "$P2P_PORT" != "$RPC_PORT" ] || P2P_PORT=$port_a

# The genesis `fees` section, as the `--fees` file the genesis command reads.
fees_args=()
if [ -n "${DEV_CHAIN_FEES:-}" ]; then
    json=""
    IFS=',' read -r -a flags <<<"$DEV_CHAIN_FEES"
    for f in "${flags[@]}"; do
        case "$f" in
            burn_base | subsidy_net_of_fees | burn_floor) json="$json${json:+,}\"$f\":true" ;;
            *) die "DEV_CHAIN_FEES: unknown flag '$f' (burn_base, subsidy_net_of_fees, burn_floor)" ;;
        esac
    done
    printf '{%s}\n' "$json" >"$DIR/fees.json"
    fees_args=(--fees "$DIR/fees.json")
fi
extra_args=()
if [ -n "${DEV_CHAIN_GENESIS_ARGS:-}" ]; then
    read -r -a extra_args <<<"$DEV_CHAIN_GENESIS_ARGS"
fi

# A test-profile genesis is refused by a release node unless the run says it is a test.
export RAND_ALLOW_TEST_FRI_PROFILE=1

{
    "$RAND_NODE_BIN" keygen --out "$DIR/validator.key.json" &&
        "$RAND_CLI" --key "$DIR/payout.key.json" keygen
} >"$DIR/setup.log" 2>&1 || die "keygen failed: $(tail -2 "$DIR/setup.log")"
PAYOUT=$("$RAND_CLI" --key "$DIR/payout.key.json" address 2>>"$DIR/setup.log" | tail -1)
case "$PAYOUT" in rand1*) ;; *) die "the wallet printed no rand1 address: $PAYOUT" ;; esac

"$RAND_NODE_BIN" genesis --chain-id "$DEV_CHAIN_ID" --fri-profile "$DEV_CHAIN_FRI_PROFILE" \
    --validator "$DIR/validator.key.json,1000,$PAYOUT" --faucet \
    ${binding_args[@]+"${binding_args[@]}"} ${fees_args[@]+"${fees_args[@]}"} ${extra_args[@]+"${extra_args[@]}"} \
    --out "$DIR/genesis.json" >>"$DIR/setup.log" 2>&1 || die "genesis failed: $(tail -2 "$DIR/setup.log")"
"$RAND_NODE_BIN" init --datadir "$DIR/data" --genesis "$DIR/genesis.json" >>"$DIR/setup.log" 2>&1 ||
    die "init failed: $(tail -2 "$DIR/setup.log")"

# Detached from this script's stdout, so a caller reading it to EOF is not held open by the node.
nohup "$RAND_NODE_BIN" run --datadir "$DIR/data" --key "$DIR/validator.key.json" --validator --no-mdns \
    --listen "/ip4/127.0.0.1/tcp/$P2P_PORT" --rpc "127.0.0.1:$RPC_PORT" \
    --block-interval-ms "$DEV_CHAIN_BLOCK_INTERVAL_MS" </dev/null >"$DIR/node.log" 2>&1 &
PID=$!
echo "$PID" >"$DIR/node.pid"

RPC_URL="http://127.0.0.1:$RPC_PORT"
deadline=$((SECONDS + 60))
until curl -sf -m 2 -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"rand_chainId","params":[]}' "$RPC_URL" 2>/dev/null |
    grep -Eq "\"result\": ?${DEV_CHAIN_ID}[,}]"; do
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "dev-chain: the node (pid $PID) exited; last lines of $DIR/node.log:" >&2
        tail -30 "$DIR/node.log" >&2
        rm -f "$DIR/node.pid"
        exit 1
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "dev-chain: $RPC_URL did not answer rand_chainId within 60 s; last lines of $DIR/node.log:" >&2
        tail -30 "$DIR/node.log" >&2
        kill "$PID" 2>/dev/null || true
        rm -f "$DIR/node.pid"
        exit 1
    fi
    sleep 0.5
done

echo "RPC_URL=$RPC_URL"
echo "GENESIS=$DIR/genesis.json"
echo "PID=$PID"
echo "DIR=$DIR"
