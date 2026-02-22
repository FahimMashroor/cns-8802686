# CNS-8802686

A network traffic analysis project for website classification using machine learning. This project implements the [VCFingerprinting](https://ieeexplore.ieee.org/abstract/document/8802686) methodology to capture, analyze, and extract features from encrypted network traffic.

## Prerequisites

### System Dependencies

- **tshark** - Wireshark CLI for packet capture
- **dig** - DNS resolution utility
- **sudo** - Root privileges required for packet capture

### Python

- Python 3.12+

## Installation

### 1. Install System Dependencies

**macOS (Homebrew):**

```bash
brew install wireshark bind
```

**Ubuntu/Debian):**

```bash
sudo apt install tshark dnsutils
```

### 2. Create Virtual Environment

```bash
# Create virtual environment (Python 3.12+)
python3.12 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Or using make:

```bash
make venv
source venv/bin/activate
```

## Quick Start

```bash
make venv && source venv/bin/activate
make install
sudo make capture
make extract
make run
```

## Makefile Commands

```text
Environment:
  venv        - Create virtual environment
  activate    - Show activation command
  deactivate  - Show deactivation command
  install     - Install Python dependencies

Dataset:
  capture     - Collect traffic from websites (sudo required)
  extract     - Extract features from PCAP files
  all         - Run full pipeline: capture + extract
  stats       - Show collection statistics

Run:
  run         - Open Jupyter notebook of paper reimplementation
```

## Manual Usage

#### Single Website Capture

Capture traffic from a single website:

```bash
sudo bash bin/capture.sh <label> <url> <num_traces>
```

**Arguments:**

- `label` - Short name for the website (e.g., `google`, `youtube`)
- `url` - Full URL to capture (e.g., `https://www.google.com`)
- `num_traces` - Number of traces to collect (default: 10)

**Example:**

```bash
sudo bash bin/capture.sh google https://www.google.com 20
```

#### Batch Collection

Capture traffic from all configured websites in parallel:

```bash
sudo bash bin/collect_all.sh
```

This collects 50 traces from each of the 7 target websites (350 total).

#### Feature Extraction

Extract statistical features from captured PCAP files:

```bash
python scripts/extract_features.py
```

## Project Structure

```
.
├── bin/
│   ├── capture.sh          # Single website traffic capture
│   └── collect_all.sh      # Parallel multi-website capture
├── scripts/
│   └── extract_features.py # Feature extraction from PCAP files
├── data/
│   ├── original/           # Original VCFingerprinting dataset
│   └── experiment/
│       ├── capture_files/  # Captured PCAP files
│       ├── trace_csv/      # Extracted feature CSV files
│       └── logs/           # Collection logs
├── docs/
│   └── 8802686.pdf         # Research paper reference
├── requirements.txt        # Python dependencies
├── Makefile               # Build commands
└── README.md              # This file
```

## Output

### PCAP Files

Location: `data/experiment/capture_files/`

Naming convention: `<label>_traceNNN.pcap`

Example:

```
google_trace001.pcap
google_trace002.pcap
...
youtube_trace050.pcap
```

### Feature CSV Files

Location: `data/experiment/trace_csv/`

Each trace generates a CSV with 19+ features including:

| Feature Category | Examples |
|-----------------|----------|
| Metadata | filename, label, duration |
| Packet Stats | total_packets, in_packets, out_packets |
| Byte Stats | total_bytes, in_bytes, out_bytes |
| Size Stats | pkt_size_mean, pkt_size_std, pkt_size_min, pkt_size_max |
| Timing Stats | ipt_mean, ipt_std, ipt_p25, ipt_p50, ipt_p75, ipt_max |
| Burst Stats | burst_count, burst_avg_size, burst_max_size |
| Sequences | packet_sizes_seq, timestamps_seq |

## Target Websites

The batch collection targets 7 websites:

1. Google (google.com)
2. YouTube (youtube.com)
3. Wikipedia (wikipedia.org)
4. Reddit (reddit.com)
5. GitHub (github.com)
6. StackOverflow (stackoverflow.com)
7. Amazon (amazon.com)

## Configuration

Key settings in `bin/capture.sh`:

- `DURATION=30` - Capture duration per trace (seconds)
- `INTERFACE="en0"` - Network interface (en0 for macOS Wi-Fi)
- `COOLDOWN=5` - Delay between traces (seconds)

Key settings in `bin/collect_all.sh`:

- `NUM_TRACES=50` - Traces per website
- `PARALLEL_JOBS=6` - Concurrent capture processes

## Troubleshooting

### Permission Denied

Packet capture requires root privileges:

```bash
sudo bash bin/capture.sh ...
```

### Interface Not Found

List available interfaces:

```bash
tshark -D
```

Update `INTERFACE` in `bin/capture.sh` if needed.

### DNS Resolution Failed

Check internet connectivity and DNS:

```bash
dig google.com
```

### Fix File Ownership After Sudo

When running `sudo make capture`, files are created as root. Fix ownership with:

```bash
sudo chown -R $(whoami) data/
```
