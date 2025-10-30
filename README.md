# 🔍 Web Reconnaissance Pipeline

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Bash](https://img.shields.io/badge/bash-4.0%2B-orange)
![Container](https://img.shields.io/badge/container-Docker%20%7C%20Podman-cyan)

**A conservative, containerized reconnaissance automation tool with intelligent target scoring for web security assessments.**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Examples](#examples) • [Contributing](#contributing)


---

## 🎯 Features

### Core Capabilities
- **🐳 Fully Containerized**: All tools run in Docker or Podman containers, eliminating dependency conflicts.
- **🧠 Intelligent Scoring System**: Automatically prioritizes high-value targets based on multiple factors.
- **⚡ Resource-Efficient**: Built-in CPU and memory limits prevent system overload.
- **🛡️ Conservative Approach**: Respects rate limits and includes comprehensive legal disclaimers.
- **📊 Structured Output**: Supports multiple formats (CSV, JSON, text) for easy analysis.

### Integrated Tools
- **Nmap**: Port discovery and service detection.
- **httpx**: Fast HTTP probing with technology detection.
- **Gobuster**: Directory and file enumeration.
- **Custom WAF/CDN Detection**: Identifies protective layers.
- **Parameter Discovery**: Finds forms and input vectors.
- **CMS Scanners**: WordPress (WPScan) and Drupal (Droopescan) vulnerability detection.

### Intelligent Features
- ✅ Automatic target prioritization (high/medium/low).
- ✅ WAF/CDN detection to avoid wasted scans.
- ✅ `robots.txt` and `sitemap.xml` parsing.
- ✅ Parameter extraction from HTML forms.
- ✅ Selective deep scanning for high-priority targets only.
- ✅ Comprehensive reporting with actionable recommendations.

---

## 📋 Requirements

### System Requirements
- **OS**: Linux (tested on Kali Linux/Ubuntu) or macOS.
- **Container Runtime**: Docker or Podman.
- **Shell**: Bash 4.0 or higher.
- **Optional**: SQLite3 (for database generation), `jq` (for JSON parsing).

### Disk Space
- ~2GB for container images (downloaded automatically on first run).
- Minimal space for output files.

---

## 🚀 Installation

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Nish344/recon-pipeline.git
   cd recon-pipeline
   ```

2. **Create wordlist directory**:
   ```bash
   mkdir -p wordlists
   ```

3. **Create a basic wordlist** (or use your own):
   ```bash
   cat > wordlists/common.txt << 'EOF'
   admin
   login
   dashboard
   api
   wp-admin
   uploads
   images
   css
   js
   robots.txt
   sitemap.xml
   .git
   backup
   test
   dev
   config
   administrator
   panel
   EOF
   ```

4. **Make script executable**:
   ```bash
   chmod +x recon-pipeline.sh
   ```

5. **Run your first scan**:
   ```bash
   ./recon-pipeline.sh --target scanme.nmap.org --output ./results
   ```

### Container Setup
The script automatically detects and uses Docker or Podman. On first run, it pulls the following container images:
- `instrumentisto/nmap`
- `projectdiscovery/httpx`
- `ghcr.io/oj/gobuster`
- `curlimages/curl`
- `python:3.11-slim`
- `wpscanteam/wpscan` (for WordPress scans)
- `droope/droopescan` (for Drupal scans)

---

## 📖 Usage

### Basic Syntax
```bash
./recon-pipeline.sh --target <TARGET> --output <OUTPUT_DIR> [OPTIONS]
```

### Required Arguments
- `--target <TARGET>`: Target IP address or hostname (e.g., `example.com` or `192.168.1.100`).
- `--output <OUTPUT_DIR>`: Directory where results will be saved.

### Optional Arguments
- `--wordlist <FILE>`: Custom wordlist for directory enumeration (default: `wordlists/common.txt`).
- `--deep`: Enable deep scanning (larger wordlists, vulnerability checks, more aggressive).
- `--threads <NUM>`: Number of threads to use (default: 10 for light, 20 for deep).
- `--timeout <SECONDS>`: Request timeout in seconds (default: 10).
- `--skip-nmap`: Skip port discovery stage (useful for web-only targets).
- `--skip-screenshots`: Skip screenshot generation.
- `--help`: Display help message.

---

## 💡 Examples

### Example 1: Basic Scan
```bash
./recon-pipeline.sh --target scanme.nmap.org --output ./results/scanme
```
**Output**: Port discovery → HTTP probing → Basic enumeration → Report

### Example 2: Deep Scan with Custom Wordlist
```bash
./recon-pipeline.sh --target example.com --output ./results/example \
  --deep --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
**Output**: Comprehensive scan with vulnerability checks and aggressive enumeration.

### Example 3: Web-Only Quick Scan
```bash
./recon-pipeline.sh --target https://example.com --output ./results/quick \
  --skip-nmap --threads 20
```
**Output**: Skips port scanning, focuses on web application.

### Example 4: Multiple Targets
```bash
for target in target1.com target2.com target3.com; do
  ./recon-pipeline.sh --target $target --output ./results/$target
  sleep 300 # 5-minute delay between scans
done
```

---

## 📊 Output Structure

The output directory contains:
```
output/
├── SUMMARY.txt                 # Quick overview of scan results
├── scored_targets.csv         # All targets with priority scores (0-10)
├── high_priority.txt          # Critical targets requiring immediate attention
├── promising.txt              # Medium priority targets
├── recommended_actions.txt    # Detailed next steps and manual verification guidance
├── findings.db                # SQLite database (if SQLite3 available)
├── waf_detected.csv           # List of targets with WAF/CDN protection
├── raw/                       # Raw tool outputs
│   ├── ports.xml              # Nmap scan results (XML)
│   ├── ports.txt              # Nmap scan results (text)
│   ├── open_ports.txt         # List of open ports
│   ├── http_ports.txt         # HTTP/HTTPS ports only
│   ├── http_probe.jsonl       # httpx JSON output
│   ├── *_gobuster.txt         # Directory enumeration results
│   ├── *_parameters.jsonl     # Discovered form parameters
│   ├── *_wpscan.json          # WordPress scan results
│   └── *_nikto.txt            # Nikto scan results (deep mode)
└── enrichment/                # Enrichment data
    ├── *_robots.txt           # robots.txt files
    ├── *_sitemap.xml          # Sitemap files
    └── *_interesting_paths.txt # Extracted from robots.txt
```

### Understanding the Scoring System
Targets are scored from **0-10** based on:
- ✅ **+2**: HTML content type.
- ✅ **+2**: Success/redirect/auth status codes (200, 30x, 401, 403).
- ✅ **+2**: Non-empty page title.
- ✅ **+3**: CMS detected (WordPress, Joomla, Drupal, etc.).
- ✅ **+3**: Admin/login paths detected.
- ❌ **-3**: Default/error pages (404, "It works", etc.).

**Priority Levels**:
- **High** (Score ≥ 7): Immediate manual inspection required.
- **Medium** (Score 4-6): Promising targets for enumeration.
- **Low** (Score < 4): Likely uninteresting or protected.

---

## 🎓 Use Cases

1. **CTF Competitions**:
   Quick recon on a CTF challenge box:
   ```bash
   ./recon-pipeline.sh --target 10.10.10.100 --output ./ctf/challenge1 --deep
   ```

2. **Bug Bounty Reconnaissance**:
   Initial assessment of a bug bounty target:
   ```bash
   ./recon-pipeline.sh --target target.com --output ./bounty/target --threads 15
   ```

3. **Penetration Testing Engagements**:
   Comprehensive client assessment:
   ```bash
   ./recon-pipeline.sh --target client.local --output ./pentest/client --deep
   ```

4. **Conservative External Attack Surface Mapping**:
   ```bash
   ./recon-pipeline.sh --target company.com --output ./redteam/company
   ```

---

## 🔐 Security & Legal

### ⚠️ LEGAL DISCLAIMER
**CRITICAL**: This tool must **ONLY** be used on systems you own or have **explicit written authorization** to test.

**Unauthorized access to computer systems is illegal** under:
- **Computer Fraud and Abuse Act (CFAA)** - United States
- **Computer Misuse Act** - United Kingdom
- Similar legislation worldwide

### Authorized Testing Sites
The following sites explicitly permit scanning for educational purposes:
- **scanme.nmap.org** - Nmap's official test server ([http://scanme.nmap.org](http://scanme.nmap.org))
- **testphp.vulnweb.com** - Acunetix test site
- **demo.testfire.net** - AltoroMutual demo banking app

### Responsible Usage
✅ **DO**:
- Obtain written permission before testing.
- Stay within agreed scope.
- Respect rate limits (max 10-12 scans per day on public test sites).
- Document all actions.
- Follow responsible disclosure.

❌ **DON'T**:
- Scan systems without authorization.
- Use for illegal activities.
- Run DoS/DDoS attacks.
- Hammer targets with excessive requests.
- Exploit vulnerabilities without permission.

**The authors assume NO liability for misuse of this tool.**

---

## 💪 Strengths

- ✅ **Containerized Architecture**: No dependency conflicts, reproducible environments.
- ✅ **Intelligent Prioritization**: Saves time by focusing on valuable targets.
- ✅ **Resource Management**: CPU/memory limits prevent system crashes.
- ✅ **Conservative Design**: Rate limiting and timeout controls.
- ✅ **Comprehensive Output**: Multiple formats for different workflows.
- ✅ **Modular Design**: Easy to add new tools or modify stages.
- ✅ **Error Handling**: Graceful failures with helpful error messages.
- ✅ **Well Documented**: Clear output and recommendations.

---

## ⚠️ Limitations

- ❌ **Linux/macOS Only**: Windows support requires WSL2.
- ❌ **No GUI**: Command-line only (terminal-based).
- ❌ **Container Dependency**: Requires Docker or Podman installation.
- ❌ **Limited Stealth**: Not designed for evasion (uses default User-Agents).
- ❌ **No Subdomain Enumeration**: Focuses on known targets only.
- ❌ **Single Target**: No built-in multi-target support (use bash loops).
- ❌ **No Real-time Monitoring**: One-time scan, not continuous.
- ❌ **Basic Vulnerability Scanning**: Not a replacement for dedicated scanners like Nessus or Burp.

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute
1. 🐛 **Report bugs** via GitHub Issues.
2. 💡 **Suggest features** or improvements.
3. 📝 **Improve documentation**.
4. 🔧 **Submit pull requests** with fixes or new features.
5. ⭐ **Star the project** if you find it useful!

### Contribution Workflow
1. **Fork the repository**:
   ```bash
   git clone https://github.com/Nish344/recon-pipeline.git
   cd recon-pipeline
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**:
   - Follow existing code style.
   - Test thoroughly on `scanme.nmap.org`.
   - Update README if needed.

4. **Commit with clear messages**:
   ```bash
   git add .
   git commit -m "Add: Description of your feature"
   ```

5. **Push and create Pull Request**:
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a PR on GitHub.

### Development Guidelines
- Keep functions small and focused.
- Add comments for complex logic.
- Test with both Docker and Podman.
- Ensure backward compatibility.
- Follow the conservative approach (respect rate limits).

---

## 📅 Roadmap

### Planned Features
- [ ] Subdomain enumeration (Subfinder, Amass integration).
- [ ] Nuclei integration for CVE-based vulnerability scanning.
- [ ] Screenshot capture (EyeWitness, Aquatone).
- [ ] API endpoint discovery (REST, GraphQL).
- [ ] JSON export format for programmatic use.
- [ ] GitHub reconnaissance (dorking for exposed secrets).
- [ ] Continuous monitoring mode (periodic rescans).
- [ ] Slack/Discord notifications for findings.
- [ ] Custom plugins system for extensibility.
- [ ] Web dashboard for visualization (optional).

### Community Requests
Have an idea? [Open an issue](https://github.com/Nish344/recon-pipeline/issues) with the `enhancement` label!

---

## 🛠️ Troubleshooting

### Common Issues
- **Problem**: `Couldn't open a raw socket. Error: Operation not permitted`
  **Solution**: Add `--cap-add=NET_RAW` to nmap container or use `-sT` scan type.
- **Problem**: `Gobuster failed: permission denied`
  **Solution**: Add `--user $(id -u):$(id -g)` to gobuster container command.
- **Problem**: `No such file or directory: wordlist`
  **Solution**: Ensure `wordlists/common.txt` exists or specify `--wordlist` with absolute path.
- **Problem**: `Docker/Podman not found`
  **Solution**: Install Docker (`sudo apt install docker.io`) or Podman (`sudo apt install podman`).
- **Problem**: Containers pull slowly
  **Solution**: Use `--cpus` and `--memory` flags to limit resources, or pull images manually first.

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**MIT License**  
Copyright (c) 2025 Nishanth

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction...

---

## 👤 Author

**Nishanth**
- 🎓 Cybersecurity Student
- 🚩 CTF Competitor
- 🔐 Penetration Testing Enthusiast
- 💻 GitHub: [@YOUR-USERNAME](https://github.com/Nish344)

---

## 🙏 Acknowledgments

Special thanks to:
- **Nmap Project**: For providing [scanme.nmap.org](http://scanme.nmap.org) for testing.
- **ProjectDiscovery**: For `httpx` and other amazing tools.
- **OJ Reeves**: For Gobuster directory enumeration.
- **WPScan Team**: For WordPress security scanner.
- **Open Source Community**: For all the security tools integrated.

### Inspired By
- reNgine
- Reconftw
- LazyRecon
- AutoRecon

---

## 📞 Support

- 📖 **Documentation**: Read this README thoroughly.
- ⭐ **Star this repo** if it helped you!

---


**⚡ Happy Hunting! ⚡**

If this tool saves you time, please consider giving it a ⭐!

[Report Bug](https://github.com/YOUR-USERNAME/recon-pipeline/issues) • [Request Feature](https://github.com/YOUR-USERNAME/recon-pipeline/issues) • [Contribute](https://github.com/YOUR-USERNAME/recon-pipeline/pulls)


---
