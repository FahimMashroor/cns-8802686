#!/bin/bash

# =============================================================================
# bin/capture.sh — Website Fingerprinting Traffic Capture
# =============================================================================
#
# WHAT IT DOES
# ─────────────
# This script automates the collection of network traffic traces for website
# fingerprinting research. For each trace, it:
#   1. Resolves the target URL's hostname to its IP addresses (IPv4 + IPv6)
#   2. Builds a BPF filter so tshark ONLY captures packets to/from those IPs
#   3. Starts a tshark (Wireshark CLI) packet capture in the background
#   4. Fetches the target URL using curl to generate real traffic
#   5. Stops the capture after a fixed duration and saves it as a .pcap file
#   6. Repeats for the requested number of traces with a cooldown in between
#
# The IP-based BPF filter ensures ONLY the target website's traffic is saved —
# background traffic from other apps, system services, or other websites will
# be excluded from every .pcap file.
#
# USAGE
# ──────
#   sudo bash bin/capture.sh <label> <url> <num_traces>
#
#   <label>       — Short name for the website (used in output filenames)
#   <url>         — Full URL to capture traffic for
#   <num_traces>  — Number of trace captures to collect (default: 10)
#
# EXAMPLES
# ─────────
#   sudo bash bin/capture.sh google      https://www.google.com    20
#   sudo bash bin/capture.sh youtube     https://www.youtube.com   20
#   sudo bash bin/capture.sh wikipedia   https://www.wikipedia.org 20
#
# OUTPUT
# ───────
#   data/experiment/capture_files/<label>_trace001.pcap
#   data/experiment/capture_files/<label>_trace002.pcap
#   ...
#
# NOTES
# ──────
#   - Must be run with sudo (tshark requires root to capture on interfaces)
#   - curl only fetches the raw HTML — it does NOT load JS, CSS, or images.
#     For more realistic full-page traffic, replace the curl block with a
#     Selenium/Playwright browser call.
#   - Run `tshark -D` to list all available network interfaces on your machine
#   - IP resolution is done once before each trace loop begins. If a CDN
#     rotates IPs mid-session, some late traces may miss a small number of
#     packets. Re-resolving per trace (slower but more accurate) can be
#     enabled by moving the resolve block inside the for loop.
# =============================================================================

set -euo pipefail
# set -e  → exit immediately if any command fails
# set -u  → treat unset variables as errors
# set -o pipefail → if a command in a pipe fails, the whole pipe fails

# ── Config ────────────────────────────────────────────────────────────────────
#
# LABEL       — Website identifier, taken from the first argument ($1).
#               Used to name output files, e.g. "google" → google_trace001.pcap
#               The :? syntax means the script will exit with an error message
#               if this argument is not provided.
#
# URL         — The target website URL to fetch during each capture, taken
#               from the second argument ($2). Must be a full URL with scheme,
#               e.g. https://www.google.com
#
# NUM_TRACES  — How many separate traces (pcap files) to collect per label.
#               Taken from the third argument ($3). Defaults to 10 if not given.
#               More traces = more robust fingerprint training data.
#               Recommended minimum: 20–30 traces per website.
#
# DURATION    — How long (in seconds) tshark captures packets for each trace.
#               curl is given (DURATION - 2) seconds to complete, leaving a
#               small buffer for tshark to catch any final packets.
#               Increase this for slow-loading or content-heavy sites.
#
# INTERFACE   — The network interface tshark listens on.
#               Common values:
#                 en0   → Wi-Fi on macOS
#                 eth0  → Ethernet on Linux
#                 wlan0 → Wi-Fi on Linux
#               Run `tshark -D` to list all interfaces on your machine.
#
# CAPTURE_DIR — Directory where .pcap files will be saved, relative to the
#               project root. The full absolute path is resolved automatically
#               below using SCRIPT_DIR, so the script works from any directory.
#
# COOLDOWN    — Seconds to wait between consecutive traces.
#               This prevents traffic from one trace bleeding into the next,
#               and lets the network and browser state settle. Recommended: 5s+
#
# ─────────────────────────────────────────────────────────────────────────────
LABEL="${1:?Usage: $0 <label> <url> <num_traces>}"
URL="${2:?Usage: $0 <label> <url> <num_traces>}"
NUM_TRACES="${3:-10}"
DURATION=30
INTERFACE="en0"
CAPTURE_DIR="data/experiment/capture_files"
COOLDOWN=5

# ── Path resolution ───────────────────────────────────────────────────────────
# Resolve the absolute path of this script's directory (project/bin/)
# then step one level up to get the project root (project/).
# This ensures CAPTURE_DIR always resolves correctly regardless of where
# the script is called from (e.g. from project/ or from project/bin/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CAPTURE_DIR="$PROJECT_ROOT/$CAPTURE_DIR"

mkdir -p "$CAPTURE_DIR"

# ── Hostname resolution ───────────────────────────────────────────────────────
# Extract the hostname from the URL (strips scheme and path).
# e.g. "https://www.google.com/search" → "www.google.com"
HOSTNAME=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')

echo "  [DNS] Resolving IPs for: $HOSTNAME"

# Resolve all IPv4 addresses for the hostname using dig.
# Multiple IPs are returned for CDN-backed sites (e.g. Google, YouTube).
# We collect all of them so tshark captures packets to any of their servers.
IPV4_LIST=$(dig +short A "$HOSTNAME" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)

# Resolve IPv6 addresses as well (many modern sites use dual-stack)
IPV6_LIST=$(dig +short AAAA "$HOSTNAME" 2>/dev/null | grep -E '^[0-9a-fA-F:]+$' || true)

if [ -z "$IPV4_LIST" ] && [ -z "$IPV6_LIST" ]; then
    echo "  [!] Could not resolve any IPs for: $HOSTNAME"
    echo "  [!] Check DNS or internet connectivity."
    exit 1
fi

echo "  [DNS] IPv4: $(echo "$IPV4_LIST" | tr '\n' ' ')"
echo "  [DNS] IPv6: $(echo "$IPV6_LIST" | tr '\n' ' ')"

# ── Build BPF capture filter ──────────────────────────────────────────────────
# BPF (Berkeley Packet Filter) is the low-level filter language used by
# tshark/tcpdump to select which packets to capture.
#
# We build a filter of the form:
#   (tcp or udp) and (host <ip1> or host <ip2> or host <ip3> ...)
#
# This ensures ONLY packets to/from the resolved target IPs are captured.
# All other traffic (background apps, OS updates, other websites) is ignored.

FILTER_PARTS=()

for IP in $IPV4_LIST $IPV6_LIST; do
    FILTER_PARTS+=("host $IP")
done

# Join all "host <ip>" parts with " or "
IP_FILTER=$(printf '%s or ' "${FILTER_PARTS[@]}")
IP_FILTER="${IP_FILTER% or }"   # strip trailing " or "

# Full BPF filter: only TCP/UDP AND only to/from our target IPs
BPF_FILTER="(tcp or udp) and ($IP_FILTER)"

echo "  [BPF] Filter: $BPF_FILTER"
echo ""

# ── Capture loop ──────────────────────────────────────────────────────────────

echo "============================================"
echo "  Website Fingerprinting — Traffic Capture"
echo "============================================"
echo "  Label     : $LABEL"
echo "  URL       : $URL"
echo "  Hostname  : $HOSTNAME"
echo "  Traces    : $NUM_TRACES"
echo "  Duration  : ${DURATION}s per trace"
echo "  Interface : $INTERFACE"
echo "  Output    : $CAPTURE_DIR"
echo "============================================"

for i in $(seq 1 "$NUM_TRACES"); do
    OUTPUT_FILE="${CAPTURE_DIR}/${LABEL}_trace$(printf '%03d' $i).pcap"
    # printf '%03d' zero-pads the trace number → 001, 002 ... 050
    # This keeps filenames sorted correctly in the filesystem

    echo ""
    echo "[*] Trace $i/$NUM_TRACES → $(basename "$OUTPUT_FILE")"

    # Launch tshark in the background (&) so the script can continue.
    # -i  → network interface to capture on
    # -a duration:N → auto-stop capture after N seconds
    # -w  → write raw packets to this .pcap file
    # -f  → BPF filter (ONLY traffic to/from our resolved target IPs)
    # -q  → quiet mode (suppress per-packet output to terminal)
    tshark -i "$INTERFACE" \
           -a duration:"$DURATION" \
           -w "$OUTPUT_FILE" \
           -f "$BPF_FILTER" \
           -q 2>/dev/null &
    TSHARK_PID=$!
    # Store tshark's process ID so we can wait for it to finish below

    # Small delay to let tshark fully initialise before generating traffic.
    # Without this, the first few packets of the page load may be missed.
    sleep 1

    # Fetch the URL to generate real network traffic during the capture window.
    # -s            → silent mode (no progress output)
    # --resolve     → force curl to use the already-resolved IP, same as tshark
    # --max-time    → abort if the request takes longer than N seconds
    # --user-agent  → mimic a real browser to avoid bot-detection responses
    # || true       → prevent set -e from exiting if curl fails (e.g. timeout)
    FIRST_IP=$(echo "$IPV4_LIST" | head -n1)
    curl -s \
         --resolve "${HOSTNAME}:443:${FIRST_IP}" \
         --resolve "${HOSTNAME}:80:${FIRST_IP}" \
         --max-time $((DURATION - 2)) \
         --user-agent "Mozilla/5.0 (X11; Linux x86_64)" \
         "$URL" > /dev/null 2>&1 || true

    # Wait for tshark to reach its duration limit and exit cleanly
    # before moving on to the next trace
    wait "$TSHARK_PID"

    # Count packets captured in this trace for a quick sanity check
    PKT_COUNT=$(tshark -r "$OUTPUT_FILE" 2>/dev/null | wc -l | tr -d ' ')
    echo "[+] Saved: $(basename "$OUTPUT_FILE")  ($PKT_COUNT packets)"

    # Cooldown between traces — skipped after the final trace
    if [ "$i" -lt "$NUM_TRACES" ]; then
        echo "    Cooling down for ${COOLDOWN}s..."
        sleep "$COOLDOWN"
    fi
done

echo ""
echo "[✓] Capture complete — $NUM_TRACES traces saved for '$LABEL'"
echo "    → $CAPTURE_DIR"