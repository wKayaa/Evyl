# Evyl Framework v3.1 - New Features Documentation

## Enhanced Security Testing Capabilities

### Laravel Framework Security Scanner

The enhanced Laravel scanner provides comprehensive security assessment for Laravel applications with ethical testing focus:

#### Features:
- **Environment File Detection**: Scans for exposed `.env` files and configuration vulnerabilities
- **Debug Interface Discovery**: Identifies publicly accessible Telescope and Ignition interfaces  
- **Configuration Exposure**: Tests for exposed Laravel configuration files
- **Log File Discovery**: Detects accessible log files that may contain sensitive information
- **Git Repository Exposure**: Identifies exposed Git repositories in Laravel projects
- **Credential Extraction**: Safely extracts configuration data for security assessment

#### Usage:
```bash
# Enable Laravel scanning (enabled by default)
python evyl.py run targets.txt --laravel

# Disable Laravel scanning
python evyl.py -f targets.txt --web --no-laravel
```

#### Detected Vulnerabilities:
- Environment file exposure (Critical)
- Debug interface exposure (High)
- Configuration file exposure (High) 
- Log file exposure (Medium)
- Git repository exposure (High)

### SMTP Security Testing Module

Legitimate SMTP service security testing for authorized penetration testing:

#### Features:
- **SMTP Service Discovery**: Port scanning for SMTP services on common ports (25, 465, 587, 2525)
- **Configuration Exposure Testing**: Scans for exposed SMTP configuration files
- **Security Assessment**: Tests for open relay vulnerabilities and STARTTLS support
- **AWS SES Analysis**: Validates AWS SES credentials and analyzes configuration security
- **Credential Extraction**: Discovers SMTP credentials in configuration files

#### Usage:
```bash
# Enable SMTP security testing (enabled by default)
python evyl.py run targets.txt --smtp

# Test specific SMTP configurations
python evyl.py -f targets.txt --validate-email --validate-ses
```

#### Security Tests:
- Open relay vulnerability testing
- STARTTLS encryption support verification
- Authentication mechanism validation
- AWS SES credential and quota validation

### Enhanced Pattern Detection

#### New Regex Patterns Added:
- **SMTP Configuration Patterns**: Host, port, username, password, encryption settings
- **Laravel Mail Configuration**: Laravel-specific mail driver and settings
- **Email Service APIs**: Enhanced coverage for AWS SES, Mailchimp, Mandrill, Elastic Email
- **Email Address Extraction**: Configuration-specific email address patterns

#### New Endpoints Added:
- **Laravel-specific paths**: 50+ Laravel framework endpoints including Telescope, Horizon, Nova
- **SMTP Configuration paths**: 20+ common SMTP configuration file locations
- **Email service endpoints**: Enhanced coverage for email service discovery

### Validation Enhancements

#### Enhanced SMTP Validator:
- **Connection Testing**: Tests SMTP service connectivity and capabilities
- **Authentication Validation**: Validates SMTP username/password combinations
- **Security Analysis**: Performs safe open relay testing and encryption support verification
- **AWS SES Validation**: Complete AWS SES credential validation with quota analysis

#### New Validation Options:
```bash
--validate-email    # Enable email service validation
--validate-ses      # Enable AWS SES validation
--crack-smtp        # Enable SMTP credential validation (renamed for clarity)
```

## Ethical Usage Guidelines

### Important Security Note
All new features are designed for **authorized security testing only**:

- ✅ **Authorized penetration testing** of systems you own or have explicit permission to test
- ✅ **Security auditing** of your own applications and infrastructure  
- ✅ **Vulnerability assessment** as part of legitimate security programs
- ✅ **Educational purposes** in controlled lab environments

- ❌ **Unauthorized access** to systems you don't own
- ❌ **Malicious exploitation** of discovered vulnerabilities
- ❌ **Spam operations** or abuse of email services
- ❌ **Bypassing security measures** for malicious purposes

### Responsible Disclosure
When vulnerabilities are discovered during authorized testing:

1. **Document findings** with appropriate detail for remediation
2. **Report to system owners** through proper channels
3. **Allow reasonable time** for patching before disclosure
4. **Follow coordinated vulnerability disclosure** best practices

## Command Examples

### Comprehensive Laravel Security Assessment
```bash
# Full Laravel security scan with validation
python evyl.py run laravel-targets.txt --laravel --validate --threads=20

# Laravel-only scan with specific modules
python evyl.py -f laravel-sites.txt --laravel --git-scanner --path-scanner
```

### SMTP Security Testing
```bash
# Complete email security assessment
python evyl.py run targets.txt --smtp --validate-email --validate-ses

# SMTP-specific testing with custom timeout
python evyl.py -f mail-servers.txt --smtp --validation-timeout=60
```

### Combined Security Assessment
```bash
# Full security assessment including new modules
python evyl.py run targets.txt --all-modules --validate --threads=50

# Targeted web application security testing
python evyl.py run web-apps.txt --web --laravel --smtp --git-scanner
```

## Sample Output

### Laravel Vulnerability Detection
```json
{
  "module": "laravel",
  "vulnerabilities": [
    {
      "type": "Environment File Exposure",
      "severity": "critical",
      "url": "https://example.com/.env",
      "description": "Laravel environment file is publicly accessible"
    }
  ],
  "credentials": [
    {
      "type": "laravel_database_credentials",
      "value": "secret_db_password",
      "source": ".env file"
    }
  ]
}
```

### SMTP Security Assessment
```json
{
  "module": "smtp",
  "smtp_services": [
    {
      "host": "mail.example.com",
      "port": 587,
      "status": "open",
      "banner": "220 mail.example.com ESMTP"
    }
  ],
  "vulnerabilities": [
    {
      "type": "Missing STARTTLS Support",
      "severity": "medium",
      "description": "SMTP server does not support STARTTLS encryption"
    }
  ]
}
```

## Integration Notes

### Module Integration
The new modules integrate seamlessly with existing Evyl Framework components:

- **Progress Display**: Real-time updates for Laravel and SMTP scanning progress
- **Validation Engine**: Automatic credential validation for discovered SMTP configurations
- **Report Generation**: JSON, HTML, and text reports include new vulnerability types
- **Telegram Notifications**: New findings are included in real-time notifications

### Performance Considerations
- **Threaded Execution**: Both modules support concurrent execution with configurable thread limits
- **Memory Efficient**: Streaming processing for large target lists
- **Rate Limiting**: Respects delay configurations to avoid overwhelming target services
- **Timeout Handling**: Configurable timeouts for network operations

### Backward Compatibility
All existing functionality remains unchanged:
- Existing command-line options continue to work
- Previous scan results formats are maintained
- Configuration files remain compatible
- No breaking changes to API or interfaces

## Troubleshooting

### Common Issues

#### Laravel Scanner
- **Permission Denied**: Some Laravel paths may be protected by .htaccess rules
- **False Positives**: Verify findings manually as some paths may return 200 but not be vulnerable
- **Rate Limiting**: Use `--delay` option if target implements rate limiting

#### SMTP Scanner  
- **Connection Timeouts**: Increase `--timeout` for slow SMTP servers
- **Firewall Blocking**: Some networks may block outbound SMTP connections
- **Authentication Required**: SMTP validation requires valid credentials for complete testing

### Performance Tuning
```bash
# For large Laravel applications
python evyl.py run targets.txt --threads=10 --delay=0.5 --timeout=30

# For SMTP-heavy environments  
python evyl.py run targets.txt --smtp --validation-timeout=60 --threads=5
```

## Contributing

To contribute improvements to the new modules:

1. **Test thoroughly** with authorized targets only
2. **Follow ethical guidelines** for all security testing features
3. **Document security implications** of any new functionality
4. **Maintain backward compatibility** with existing features
5. **Include proper error handling** and logging

## Legal Disclaimer

**CRITICAL**: These enhanced capabilities are provided for authorized security testing only. Users must:

- ✅ Obtain explicit written permission before testing any systems
- ✅ Comply with all applicable laws and regulations
- ✅ Respect terms of service and acceptable use policies  
- ✅ Use findings responsibly and ethically

**Unauthorized use of these tools is illegal and unethical. Users are solely responsible for ensuring compliance with applicable laws.**