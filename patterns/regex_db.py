"""
Comprehensive Regex Pattern Database for Evyl Framework

Contains 25+ advanced regex patterns for detecting various types of credentials
and sensitive information across cloud platforms, email services, databases, and more.
"""

import re

# Compiled regex patterns for better performance
PATTERNS = {
    # AWS Credentials
    'aws_access_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    'aws_secret_key': r'(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|aws[_\-]?secret)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
    'aws_session_token': r'(?:aws[_\-]?session[_\-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{16,})["\']?',
    
    # Google Cloud Platform
    'gcp_service_account': r'-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\+/=\s]+-----END PRIVATE KEY-----',
    'gcp_api_key': r'AIza[0-9A-Za-z\\-_]{35}',
    'gcp_oauth_token': r'ya29\.[0-9A-Za-z\-_]+',
    
    # Azure
    'azure_storage_account': r'DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]+;EndpointSuffix=core.windows.net',
    'azure_client_secret': r'[a-zA-Z0-9~\-_.]{34,40}',
    'azure_tenant_id': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    
    # Email Service APIs
    'sendgrid': r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    'mailgun': r'key-[a-f0-9]{32}',
    'mailgun_public': r'pubkey-[a-f0-9]{32}',
    'postmark': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
    'sparkpost': r'[a-f0-9]{40}',
    'brevo': r'xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}',
    
    # SMS/Communication Services
    'twilio_account_sid': r'AC[a-f0-9]{32}',
    'twilio_auth_token': r'[a-f0-9]{32}',
    'twilio_api_key': r'SK[a-f0-9]{32}',
    'slack_token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
    'discord_token': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
    
    # Database Credentials
    'mysql_connection': r'mysql://[a-zA-Z0-9_]+:[a-zA-Z0-9_@#$%^&*()]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
    'postgres_connection': r'postgres(?:ql)?://[a-zA-Z0-9_]+:[a-zA-Z0-9_@#$%^&*()]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
    'mongodb_connection': r'mongodb://[a-zA-Z0-9_]+:[a-zA-Z0-9_@#$%^&*()]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
    'redis_connection': r'redis://[a-zA-Z0-9_]*:?[a-zA-Z0-9_@#$%^&*()]*@[a-zA-Z0-9.-]+:[0-9]+/?[0-9]*',
    
    # API Keys and Tokens
    'github_token': r'(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}',
    'gitlab_token': r'glpat-[a-zA-Z0-9\-_]{20}',
    'bitbucket_token': r'(?:ATBB|ATCL)[a-zA-Z0-9]{32}',
    'stripe_key': r'(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24}',
    'paypal_client_id': r'A[a-zA-Z0-9]{80}',
    
    # JWT Tokens
    'jwt_token': r'eyJ[a-zA-Z0-9\-_=]+\.eyJ[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_.+/=]*',
    
    # SSH Keys
    'ssh_private_key': r'-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----[a-zA-Z0-9\+/=\s]+-----END (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----',
    'ssh_public_key': r'ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]+',
    
    # Kubernetes Secrets
    'kubernetes_token': r'(?:ey[A-Za-z0-9\-_=]+\.){2}[A-Za-z0-9\-_.+/=]*',
    'kubernetes_secret': r'[a-zA-Z0-9\-_]{32,}',
    
    # Generic Secrets
    'generic_api_key': r'(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{16,})["\']?',
    'generic_password': r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,})["\']?',
    'generic_secret': r'(?:secret|private[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{16,})["\']?',
    
    # Common Environment Variables
    'env_database_url': r'(?:DATABASE_URL|DB_URL)\s*[:=]\s*["\']?([a-zA-Z0-9+/:@.-]+)["\']?',
    'env_redis_url': r'(?:REDIS_URL|CACHE_URL)\s*[:=]\s*["\']?([a-zA-Z0-9+/:@.-]+)["\']?',
    'env_mail_url': r'(?:MAIL_URL|SMTP_URL)\s*[:=]\s*["\']?([a-zA-Z0-9+/:@.-]+)["\']?',
    
    # Cryptocurrency
    'bitcoin_private_key': r'(?:[5KL][1-9A-HJ-NP-Za-km-z]{50,51})',
    'ethereum_private_key': r'(?:0x)?[a-fA-F0-9]{64}',
    
    # OAuth and Social Media
    'facebook_access_token': r'EAA[a-zA-Z0-9]{200,}',
    'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'twitter_bearer_token': r'AAAA[a-zA-Z0-9%]{80,}',
}

# Compiled patterns for better performance
COMPILED_PATTERNS = {name: re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                    for name, pattern in PATTERNS.items()}

def find_credentials(text: str) -> list:
    """
    Find all credentials in the given text using all patterns
    
    Args:
        text (str): Text to search for credentials
        
    Returns:
        list: List of found credentials with metadata
    """
    found_credentials = []
    
    for pattern_name, compiled_pattern in COMPILED_PATTERNS.items():
        for match in compiled_pattern.finditer(text):
            credential = {
                'type': pattern_name,
                'value': match.group(0),
                'start': match.start(),
                'end': match.end(),
                'line': text[:match.start()].count('\n') + 1,
                'context': text[max(0, match.start()-50):match.end()+50]
            }
            found_credentials.append(credential)
    
    return found_credentials

def validate_pattern(pattern_name: str, text: str) -> bool:
    """
    Validate if text matches a specific pattern
    
    Args:
        pattern_name (str): Name of the pattern to check
        text (str): Text to validate
        
    Returns:
        bool: True if pattern matches, False otherwise
    """
    if pattern_name not in COMPILED_PATTERNS:
        return False
    
    return bool(COMPILED_PATTERNS[pattern_name].search(text))

def get_pattern_names() -> list:
    """Get list of all available pattern names"""
    return list(PATTERNS.keys())

def get_patterns_by_category() -> dict:
    """Get patterns organized by category"""
    categories = {
        'aws': [k for k in PATTERNS.keys() if k.startswith('aws_')],
        'gcp': [k for k in PATTERNS.keys() if k.startswith('gcp_')],
        'azure': [k for k in PATTERNS.keys() if k.startswith('azure_')],
        'email': ['sendgrid', 'mailgun', 'mailgun_public', 'postmark', 'sparkpost', 'brevo'],
        'sms': ['twilio_account_sid', 'twilio_auth_token', 'twilio_api_key'],
        'social': ['slack_token', 'discord_token', 'facebook_access_token', 'twitter_bearer_token'],
        'git': ['github_token', 'gitlab_token', 'bitbucket_token'],
        'database': [k for k in PATTERNS.keys() if 'connection' in k or k.startswith('env_')],
        'crypto': ['bitcoin_private_key', 'ethereum_private_key'],
        'ssh': ['ssh_private_key', 'ssh_public_key'],
        'kubernetes': ['kubernetes_token', 'kubernetes_secret'],
        'generic': [k for k in PATTERNS.keys() if k.startswith('generic_')],
        'payment': ['stripe_key', 'paypal_client_id'],
        'jwt': ['jwt_token'],
        'oauth': ['google_oauth']
    }
    
    return categories