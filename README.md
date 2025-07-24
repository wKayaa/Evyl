# 🔥 Evyl Framework v3.0

<div align="center">

![Evyl Framework](https://img.shields.io/badge/Evyl-Framework%20v3.0-red?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Advanced Cloud Exploitation Framework for Authorized Security Testing**

*Comprehensive credential harvesting and cloud exploitation toolkit with optimized performance*

</div>

## 🎯 Overview

Evyl Framework v3.0 is a production-ready Python exploitation framework designed for authorized security testing. It provides comprehensive capabilities for:

- **🌐 Multi-Cloud Platform Testing**: AWS, GCP, Azure, Kubernetes
- **🔍 Credential Discovery**: 1500+ vulnerable endpoints across cloud services
- **✅ Automatic Validation**: Real-time credential verification
- **📊 Optimized Progress Monitoring**: High-performance real-time UI with statistics
- **🛡️ Advanced Evasion**: Proxy rotation, user-agent spoofing, rate limiting
- **🌐 Multi-Language Support**: English/French UI with configurable display

## ✨ Key Features

### 🎯 Target Discovery & Exploitation
- **Kubernetes Clusters**: Service account tokens, API enumeration, pod escape
- **AWS Infrastructure**: Metadata service, IAM credentials, S3 enumeration
- **GCP Resources**: Service accounts, access tokens, project enumeration  
- **Azure Assets**: Managed identities, access tokens, subscription discovery
- **Web Applications**: Git exposure, configuration files, backup discovery

### 🔐 Credential Harvesting
- **25+ Advanced Regex Patterns**: AWS keys, API tokens, database URLs
- **Real-time Extraction**: Live credential discovery during scanning
- **Context Analysis**: Line numbers, surrounding code, source URLs
- **Deduplication**: Intelligent filtering of duplicate findings

### ✅ Validation Engine
- **AWS**: STS calls, S3 enumeration, SES quota checks
- **Email Services**: SendGrid, Mailgun, Postmark, SparkPost, Brevo
- **SMS Services**: Twilio account validation
- **Database**: MySQL, PostgreSQL, MongoDB, Redis connections

### 📊 High-Performance Progress Display
```
🔍 EVYL SCANNER V3.0 - SCAN IN PROGRESS 🔍

📁 File: domains-list-hq.txt
⏱️ Elapsed time: 73s 33m 21s  
📊 Progress: [████████████████████████████████████] 88.4%

📈 TOTAL STATS:
🌐 URLs processed: 5,566,407
🎯 Unique URLs: 4,475,128
✅ URLs validated: 1,001,339
📉 Success rate: 88.4%

🏆 HITS FOUND (TOTAL: 2,808):
✅ AWS: 342  ✅ SendGrid: 156  ✅ Brevo: 89  ✅ SMTP: 134
✅ Postmark: 78  ✅ SparkPost: 45  ✅ Mailgun: 67  ✅ Twilio: 32

💻 CPU: 100.0% | 🧠 RAM: 8141.2 MB | 📡 HTTP: 2,341/s | ⏰ 15:30:45
```

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/wKayaa/Evyl.git
cd Evyl

# Install dependencies
pip install -r requirements.txt

# Or install with setup.py
pip install -e .
```

### Docker Installation

```bash
# Build Docker image
docker build -t evyl-framework .

# Run with Docker
docker run -v $(pwd)/results:/app/results evyl-framework -f targets.txt
```

### Basic Usage

```bash
# Scan single target
python evyl.py -t https://example.com

# Scan multiple targets from file
python evyl.py -f targets.txt -o results/

# Enable all modules with validation
python evyl.py -f domains.txt --all-modules --validate

# High-performance scan
python evyl.py -f targets.txt --threads 100 --timeout 5

# Kubernetes-specific scan
python evyl.py -t k8s-cluster.com --kubernetes

# Cloud metadata exploitation
python evyl.py -t ec2-instance.aws.com --aws --gcp --azure
```

## 📋 Command Line Options

### Target Options
```bash
-f, --file FILE           Target file containing URLs/domains
-t, --target TARGET       Single target (can be used multiple times)
```

### Scanning Options
```bash
--threads N               Number of threads (default: 50)
--timeout N               Request timeout in seconds (default: 10)  
--retries N               Number of retries per request (default: 3)
--delay FLOAT             Delay between requests (default: 0)
```

### Module Options
```bash
--kubernetes              Enable Kubernetes scanning
--aws                     Enable AWS scanning
--gcp                     Enable GCP scanning  
--azure                   Enable Azure scanning
--web                     Enable web application scanning
--all-modules             Enable all scanning modules
```

### Validation Options
```bash
--validate                Validate found credentials
--validation-timeout N    Validation timeout in seconds (default: 30)
```

### Output Options
```bash
-o, --output-dir DIR      Output directory (default: results)
--format FORMAT           Output format: json, html, txt, all
--encrypt                 Encrypt output files
```

### Network Options
```bash
--proxy PROXY             HTTP proxy (http://host:port)
--proxy-file FILE         File containing proxy list
--user-agent UA           Custom User-Agent string
--headers JSON            Custom headers (JSON format)
```

## 🏗️ Architecture

### Core Components

```
evyl.py                   # Main CLI entry point with rich UI
├── core/
│   ├── scanner.py        # Multi-threaded scanning engine
│   ├── exploiter.py      # Exploit orchestrator
│   ├── validator.py      # Credential validation engine
│   └── reporter.py       # Multi-format report generator
├── modules/
│   ├── kubernetes/       # Kubernetes exploitation
│   ├── cloud/           # Cloud platform scanners  
│   ├── web/             # Web application modules
│   └── exploits/        # Generic vulnerability scanners
├── validators/
│   ├── aws.py           # AWS credential validator
│   ├── email.py         # Email service validators
│   └── sms.py           # SMS service validators  
└── utils/
    ├── logger.py        # Colored logging system
    ├── network.py       # HTTP client with evasion
    ├── progress.py      # Real-time progress display
    └── crypto.py        # Encryption utilities
```

### Pattern Database

The framework includes comprehensive pattern databases:

- **25+ Regex Patterns**: AWS, GCP, Azure, email services, databases
- **1500+ Endpoints**: Kubernetes, cloud metadata, web applications
- **File Signatures**: Automatic file type detection
- **Sensitive Patterns**: Configuration files, backups, logs

## 🎯 Scanning Modules

### Kubernetes Module
- **Service Account Tokens**: Automatic token extraction
- **API Enumeration**: Comprehensive Kubernetes API scanning
- **Pod Escape**: Container breakout techniques
- **etcd Exploitation**: Direct etcd database access
- **Kubelet Scanning**: Worker node enumeration

### Cloud Modules

#### AWS Scanner
- **Metadata Service**: IMDSv1/v2 exploitation
- **IAM Credentials**: Role-based credential extraction
- **User Data**: Sensitive information in instance metadata
- **S3 Enumeration**: Bucket discovery and access testing

#### GCP Scanner  
- **Service Accounts**: Account enumeration and token extraction
- **Metadata API**: Comprehensive metadata service scanning
- **Access Tokens**: OAuth token harvesting
- **Project Discovery**: GCP project information gathering

#### Azure Scanner
- **Managed Identity**: Identity service exploitation  
- **Access Tokens**: Multi-resource token extraction
- **Instance Metadata**: VM information gathering
- **Subscription Discovery**: Azure subscription enumeration

### Web Application Module
- **Git Exposure**: Complete .git directory reconstruction
- **Configuration Files**: .env, config.json, settings discovery
- **Backup Files**: Database dumps, archive discovery
- **JavaScript Analysis**: Client-side secret extraction

## 🔧 Configuration

### settings.yaml
```yaml
scanner:
  threads: 100
  timeout: 10
  user_agent_rotation: true
  proxy_rotation: true

validation:
  enabled: true
  parallel_validations: 10
  timeout: 30

output:
  formats: ["json", "html", "txt"]
  encrypt_results: false
  real_time_alerts: true
```

### User Agents & Proxies
- **500+ User Agents**: Chrome, Firefox, Safari, mobile browsers
- **Proxy Support**: HTTP, HTTPS, SOCKS5 with authentication
- **Rotation Logic**: Intelligent rotation to avoid detection

## 📊 Output Formats

### JSON Report
```json
{
  "scan_id": "uuid-here",
  "timestamp": "2025-01-20T02:51:25Z",
  "statistics": {
    "urls_processed": 5566407,
    "total_hits": 2808,
    "success_rate": 88.4
  },
  "findings": {
    "aws": [
      {
        "type": "aws_credentials", 
        "access_key": "AKIA...",
        "status": "VALID",
        "permissions": ["s3:*", "ec2:*"],
        "source": "https://example.com/.env"
      }
    ]
  }
}
```

### HTML Report
- **Interactive Dashboard**: Sortable tables, search functionality
- **Visual Statistics**: Charts and graphs
- **Export Options**: CSV, PDF export capabilities
- **Responsive Design**: Mobile-friendly interface

## 🛡️ Security & Evasion

### Network Evasion
- **User-Agent Rotation**: 500+ realistic browser agents
- **Proxy Rotation**: Support for proxy chains and authentication
- **Rate Limiting**: Configurable delays and request spacing
- **SSL Bypass**: Certificate verification bypass options

### Anti-Detection
- **Request Randomization**: Random headers and timing
- **Connection Pooling**: Efficient connection reuse  
- **CloudFlare Bypass**: Advanced bypass techniques
- **Retry Logic**: Exponential backoff with jitter

### Security Features
- **Memory Wiping**: Secure credential handling
- **Encrypted Storage**: AES encryption for sensitive results
- **Secure Deletion**: Multi-pass file wiping
- **Credential Obfuscation**: Safe logging of sensitive data

## 📈 Performance

### Optimizations
- **Multi-threading**: Up to 100+ concurrent threads
- **Connection Pooling**: HTTP/2 connection reuse
- **Async I/O**: Non-blocking network operations
- **Memory Efficiency**: Streaming processing for large datasets

### Benchmarks
- **Processing Speed**: 1000+ URLs/second
- **Memory Usage**: <500MB for large scans
- **Concurrent Threads**: 100+ threads supported
- **Response Time**: <5ms average processing per URL

## 🔬 Advanced Usage

### Custom Patterns
```python
# Add custom regex patterns
from patterns.regex_db import PATTERNS

PATTERNS['custom_token'] = r'custom-[a-f0-9]{32}'
```

### Plugin Development
```python
# Create custom scanner module
class CustomScanner:
    async def scan(self, target: str) -> Dict[str, Any]:
        # Custom scanning logic
        return {'vulnerabilities': [], 'credentials': []}
```

### Validation Extensions
```python
# Custom credential validator
class CustomValidator:
    async def validate(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        # Custom validation logic
        return {'status': 'valid', 'details': {}}
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/wKayaa/Evyl.git
cd Evyl

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is intended for authorized security testing only. Users are responsible for:

- ✅ Obtaining proper authorization before testing any systems
- ✅ Complying with applicable laws and regulations  
- ✅ Respecting terms of service and acceptable use policies
- ✅ Using the tool ethically and responsibly

**Unauthorized access to computer systems is illegal and unethical.**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Cloud security research community
- Open source security tools that inspired this project
- Beta testers and contributors
- Security researchers who provided feedback

---

<div align="center">

**Made with ❤️ by the Evyl Team**

[🌐 Website](https://evyl.dev) • [📚 Documentation](https://github.com/wKayaa/Evyl/wiki) • [🐛 Issues](https://github.com/wKayaa/Evyl/issues) • [💬 Discussions](https://github.com/wKayaa/Evyl/discussions)

</div>
