# 🚀 High-Performance Web Server Access Log Analyzer

A production-ready, memory-efficient Command Line Interface (CLI) tool engineered in Python to analyze large-scale web server access logs (e.g., Nginx and Apache).

Built using an object-oriented architecture, the analyzer processes log files as streams, maintaining a near-zero memory footprint even when handling multi-gigabyte datasets.

Beyond basic log parsing, the project includes advanced statistical aggregation, automated security anomaly detection, and data visualization.

---

# ✨ Features

## 📦 Core Engineering

- **Stream-Based Parsing**
  - Processes log files line by line using generators.
  - Maintains **O(1)** auxiliary memory complexity.

- **Robust Data Sanitization**
  - Filters corrupted, malformed, or incomplete log entries using strict Regular Expressions.

- **Traffic Analytics**
  - Counts total requests.
  - Calculates unique client IP addresses.
  - Reports successful requests.
  - Displays the top **N** requested endpoints.

---

## ⚡ Advanced Features

### 📦 Gzip Support
- Reads compressed `.gz` log files directly without extraction.

### ⏰ Time Window Filtering
- Analyze only specific hours using:

```bash
--start <hour>
--end <hour>
```

### 🛡️ Security Monitoring
- Detects repeated **401 Unauthorized** and **403 Forbidden** responses from individual clients to identify potential brute-force attacks.

### 📈 Infrastructure Anomaly Detection
- Identifies abnormal spikes in **5xx Server Errors** using statistical threshold analysis.

### 📄 JSON Export
- Export the complete analysis as a structured JSON document.

### 📊 Automatic Visualization
- Generates a high-resolution traffic distribution chart:

```
hourly_traffic.png
```

---

# 🏗️ Project Structure

The project follows the **Separation of Concerns (SoC)** and **Single Responsibility Principle (SRP)**.

```text
.
├── analyzer.py       # CLI entry point & orchestration
├── models.py         # Data models & regex parsing
├── stats.py          # Traffic analytics & visualization
└── security.py       # Security monitoring & anomaly detection
```

---

# 🚀 Installation

## Requirements

- Python 3.8+
- matplotlib

Navigate to the project root directory:

```bash
cd log_analyzer
```

Install dependencies:

```bash
pip install matplotlib
```

---

# 💻 Usage

Run the analyzer using:

```bash
python analyzer.py <log_file> [options]
```

---

# 🎛️ Command-Line Options

| Option | Type | Default | Description |
|---------|------|---------|-------------|
| `log_file` | String | **Required** | Path to the log file (`.log` or `.gz`) |
| `--top` | Integer | `10` | Number of most requested endpoints |
| `--start` | Integer | `0` | Start hour (0–23) |
| `--end` | Integer | `23` | End hour (0–23) |
| `--json` | String | None | Export results to a JSON file |

---

# 💡 Examples

## Basic Analysis

```bash
python analyzer.py access.log
```

---

## Analyze a Compressed Log

```bash
python analyzer.py archived_logs.log.gz
```

---

## Export Results to JSON

```bash
python analyzer.py access.log --json production_audit.json
```

---

# 📊 Visualization

When running in normal CLI mode, the analyzer automatically generates:

```
hourly_traffic.png
```

The chart illustrates hourly traffic distribution, helping DevOps engineers identify:

- Peak traffic periods
- Low-load maintenance windows
- Infrastructure bottlenecks
- Usage patterns

---

# 🛡️ Security Analysis

The analyzer automatically reports:

- Suspicious clients with repeated **401/403** responses
- Potential brute-force attempts
- Hourly **5xx** error spikes
- Infrastructure anomalies

---

## 🧠 Technical Decisions & Lessons Learned

### 1. Architectural Strategy: Modular and Object-Oriented Design
- **The Decision**: To ensure the main execution context remains clean and uncluttered, the entire application was engineered using highly localized, single-purpose functions. Furthermore, by introducing the **Object-Oriented Programming (OOP)** paradigm, data manipulation and subsequent statistical analyses became significantly more streamlined.
- **The Outcome**: Separating the functional core from the dedicated statistics and security analytical layers maximizes code reusability and ensures effortless future extensibility.

### 2. Major Bug Encountered & Resolution: Handling Corrupted Log Structures
- **The Challenge**: During early execution, incoming malformed or corrupted log sequences consistently threatened to trigger unexpected system terminations or halt the processing stream entirely.
- **The Fix**: To counteract this vulnerability, I exhaustively designed and tested specialized, robust Regular Expression patterns. This rigorous regex filtering successfully isolated the malformed data streams, preventing pipeline failures while drastically improving the accuracy and quality of data extraction.

---

# 📜 License

This project is released under the **MIT License**.