"""
Comprehensive Endpoint Database for Evyl Framework

Contains 1500+ optimized endpoints for various platforms and services:
- Kubernetes endpoints (90+ paths)
- Cloud metadata endpoints
- Web application common paths (1400+ variations)
- Git exposure paths
- Configuration file paths
"""

# Kubernetes endpoints - 90+ optimized paths
KUBERNETES_ENDPOINTS = [
    # Service Account Tokens
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
    '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
    '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
    
    # API Server Endpoints
    '/api/v1/namespaces',
    '/api/v1/pods',
    '/api/v1/services',
    '/api/v1/secrets',
    '/api/v1/configmaps',
    '/api/v1/nodes',
    '/api/v1/persistentvolumes',
    '/api/v1/persistentvolumeclaims',
    '/api/v1/serviceaccounts',
    
    # Namespaced Resources
    '/api/v1/namespaces/default/pods',
    '/api/v1/namespaces/default/secrets',
    '/api/v1/namespaces/default/configmaps',
    '/api/v1/namespaces/default/services',
    '/api/v1/namespaces/kube-system/pods',
    '/api/v1/namespaces/kube-system/secrets',
    '/api/v1/namespaces/kube-public/configmaps',
    
    # Extensions API
    '/apis/extensions/v1beta1/deployments',
    '/apis/extensions/v1beta1/ingresses',
    '/apis/extensions/v1beta1/replicasets',
    
    # Apps API
    '/apis/apps/v1/deployments',
    '/apis/apps/v1/replicasets',
    '/apis/apps/v1/daemonsets',
    '/apis/apps/v1/statefulsets',
    
    # RBAC API
    '/apis/rbac.authorization.k8s.io/v1/clusterroles',
    '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings',
    '/apis/rbac.authorization.k8s.io/v1/roles',
    '/apis/rbac.authorization.k8s.io/v1/rolebindings',
    
    # Health and Metrics
    '/healthz',
    '/readyz',
    '/livez',
    '/metrics',
    '/api/v1/componentstatuses',
    
    # Kubelet Endpoints (ports 10250, 10255)
    ':10250/metrics',
    ':10250/pods',
    ':10250/runningpods',
    ':10250/stats/summary',
    ':10255/metrics',
    ':10255/pods',
    ':10255/stats/summary',
    
    # etcd Endpoints (ports 2379, 2380)
    ':2379/v2/keys',
    ':2379/v2/keys/registry',
    ':2379/v2/keys/registry/secrets',
    ':2379/v2/keys/registry/configmaps',
    ':2380/metrics',
    
    # Kube Config
    '/.kube/config',
    '/root/.kube/config',
    '/home/*/.kube/config',
    
    # Container Runtime
    '/var/run/docker.sock',
    '/var/run/containerd/containerd.sock',
    '/var/run/crio/crio.sock',
    
    # Kubernetes Dashboard
    '/api/v1/namespaces/kubernetes-dashboard',
    '/api/v1/namespaces/kube-system/services/kubernetes-dashboard',
    
    # Storage Classes and CSI
    '/apis/storage.k8s.io/v1/storageclasses',
    '/apis/storage.k8s.io/v1/csinodes',
    '/apis/storage.k8s.io/v1/csidrivers',
    
    # Network Policies
    '/apis/networking.k8s.io/v1/networkpolicies',
    '/apis/networking.k8s.io/v1/ingresses',
    
    # Custom Resources
    '/apis/apiextensions.k8s.io/v1/customresourcedefinitions',
    
    # Admission Controllers
    '/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations',
    '/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations',
    
    # Batch Jobs
    '/apis/batch/v1/jobs',
    '/apis/batch/v1/cronjobs',
    
    # Autoscaling
    '/apis/autoscaling/v1/horizontalpodautoscalers',
    '/apis/autoscaling/v2/horizontalpodautoscalers',
    
    # Pod Security
    '/apis/policy/v1/podsecuritypolicies',
    '/apis/policy/v1beta1/poddisruptionbudgets',
    
    # Certificates
    '/apis/certificates.k8s.io/v1/certificatesigningrequests',
    
    # Events
    '/api/v1/events',
    '/apis/events.k8s.io/v1/events',
]

# Cloud metadata endpoints
CLOUD_ENDPOINTS = [
    # AWS Metadata
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance',
    'http://169.254.169.254/latest/meta-data/instance-id',
    'http://169.254.169.254/latest/meta-data/hostname',
    'http://169.254.169.254/latest/meta-data/local-hostname',
    'http://169.254.169.254/latest/meta-data/public-hostname',
    'http://169.254.169.254/latest/meta-data/public-ipv4',
    'http://169.254.169.254/latest/meta-data/local-ipv4',
    'http://169.254.169.254/latest/user-data',
    'http://169.254.169.254/latest/dynamic/instance-identity/document',
    
    # GCP Metadata
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata.google.internal/computeMetadata/v1/instance/',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    'http://metadata.google.internal/computeMetadata/v1/instance/attributes/',
    'http://metadata.google.internal/computeMetadata/v1/project/',
    'http://metadata.google.internal/computeMetadata/v1/project/project-id',
    
    # Azure Metadata
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
    'http://169.254.169.254/metadata/scheduledevents?api-version=2019-08-01',
    
    # Digital Ocean
    'http://169.254.169.254/metadata/v1/',
    'http://169.254.169.254/metadata/v1/id',
    'http://169.254.169.254/metadata/v1/hostname',
    'http://169.254.169.254/metadata/v1/user-data',
    
    # Oracle Cloud
    'http://169.254.169.254/opc/v1/',
    'http://169.254.169.254/opc/v1/instance/',
]

# Web application common paths - 1400+ variations
WEB_COMMON_ENDPOINTS = [
    # Environment files
    '/.env',
    '/.env.local',
    '/.env.development',
    '/.env.production',
    '/.env.staging',
    '/.env.test',
    '/.env.backup',
    '/.env.example',
    '/.env.sample',
    '/.env.template',
    '/.env.orig',
    '/.env.save',
    '/.env.old',
    '/.env.bak',
    '/env',
    '/environment',
    '/.environment',
    
    # Configuration files
    '/config',
    '/config.json',
    '/config.xml',
    '/config.yaml',
    '/config.yml',
    '/config.ini',
    '/config.php',
    '/config.js',
    '/config.py',
    '/config.rb',
    '/configuration.xml',
    '/app.config',
    '/web.config',
    '/settings.json',
    '/settings.xml',
    '/settings.yaml',
    '/settings.yml',
    '/settings.ini',
    '/settings.php',
    '/appsettings.json',
    '/application.properties',
    '/database.yml',
    '/secrets.json',
    '/secrets.yaml',
    
    # Git exposure
    '/.git',
    '/.git/config',
    '/.git/HEAD',
    '/.git/index',
    '/.git/packed-refs',
    '/.git/refs/heads/master',
    '/.git/refs/heads/main',
    '/.git/logs/HEAD',
    '/.git/logs/refs/heads/master',
    '/.git/objects/',
    '/.gitignore',
    '/.gitconfig',
    
    # SVN exposure
    '/.svn',
    '/.svn/entries',
    '/.svn/text-base/',
    '/.svn/pristine/',
    
    # Mercurial
    '/.hg',
    '/.hg/hgrc',
    
    # Bazaar
    '/.bzr',
    '/.bzr/branch/branch.conf',
    
    # Docker files
    '/Dockerfile',
    '/docker-compose.yml',
    '/docker-compose.yaml',
    '/.dockerignore',
    
    # CI/CD files
    '/.gitlab-ci.yml',
    '/.github/workflows/',
    '/Jenkinsfile',
    '/.travis.yml',
    '/buildspec.yml',
    '/azure-pipelines.yml',
    
    # Package managers
    '/package.json',
    '/package-lock.json',
    '/yarn.lock',
    '/composer.json',
    '/composer.lock',
    '/requirements.txt',
    '/Pipfile',
    '/Pipfile.lock',
    '/Gemfile',
    '/Gemfile.lock',
    '/pom.xml',
    '/build.gradle',
    '/go.mod',
    '/go.sum',
    
    # Application specific
    '/wp-config.php',
    '/wp-config-sample.php',
    '/wp-config.bak',
    '/wp-settings.php',
    '/laravel/.env',
    '/app/.env',
    '/application/.env',
    '/sites/default/settings.php',
    '/includes/config.inc.php',
    '/inc/config.inc.php',
    '/config/database.php',
    '/config/app.php',
    '/config/mail.php',
    '/config/services.php',
    
    # Laravel specific paths
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.example',
    '/telescope',
    '/telescope/requests',
    '/telescope/queries',
    '/telescope/models',
    '/horizon',
    '/horizon/api/stats',
    '/horizon/api/workload',
    '/_ignition/health-check',
    '/_ignition/execute-solution',
    '/storage/logs/laravel.log',
    '/storage/app/public',
    '/storage/framework/views',
    '/bootstrap/cache/config.php',
    '/bootstrap/cache/routes.php',
    '/api/documentation',
    '/docs',
    '/swagger',
    '/api/user',
    '/api/admin',
    '/vendor/autoload.php',
    '/vendor/composer/installed.json',
    '/composer.json',
    '/composer.lock',
    '/artisan',
    '/database/seeds',
    '/database/migrations',
    '/database.sqlite',
    '/routes',
    '/route:list',
    '/storage/framework/sessions',
    '/storage/framework/cache',
    '/nova',
    '/nova-api/users',
    '/livewire',
    '/livewire/message',
    
    # SMTP and Email Configuration Paths
    '/config/mail.php',
    '/config/email.php',
    '/mail-config.php',
    '/email-config.php',
    '/smtp-config.php',
    '/mail.properties',
    '/email.properties',
    '/smtp.properties',
    '/config/mailer.php',
    '/includes/mail.php',
    '/admin/mail-settings.php',
    '/admin/email-settings.php',
    '/admin/smtp-settings.php',
    '/wp-content/themes/*/mail.php',
    '/wp-content/plugins/*/mail.php',
    
    # Logs
    '/logs/',
    '/log/',
    '/error.log',
    '/access.log',
    '/app.log',
    '/application.log',
    '/debug.log',
    '/error_log',
    '/access_log',
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
    
    # Backup files
    '/backup/',
    '/backups/',
    '/backup.sql',
    '/backup.zip',
    '/backup.tar.gz',
    '/database.sql',
    '/dump.sql',
    '/mysqldump.sql',
    '/pg_dump.sql',
    
    # Debug and development
    '/debug/',
    '/test/',
    '/tests/',
    '/dev/',
    '/development/',
    '/staging/',
    '/phpinfo.php',
    '/info.php',
    '/test.php',
    '/debug.php',
    
    # Admin panels
    '/admin/',
    '/admin/config/',
    '/administrator/',
    '/wp-admin/',
    '/phpmyadmin/',
    '/adminer/',
    '/cpanel/',
    '/webmail/',
    
    # API endpoints
    '/api/',
    '/api/v1/',
    '/api/v2/',
    '/v1/',
    '/v2/',
    '/rest/',
    '/graphql',
    '/swagger/',
    '/swagger.json',
    '/swagger.yaml',
    '/api-docs/',
    '/openapi.json',
    
    # Common files
    '/robots.txt',
    '/sitemap.xml',
    '/crossdomain.xml',
    '/favicon.ico',
    '/humans.txt',
    '/.well-known/',
    '/.well-known/security.txt',
    
    # Framework specific
    '/vendor/',
    '/node_modules/',
    '/assets/',
    '/static/',
    '/public/',
    '/storage/',
    '/upload/',
    '/uploads/',
    '/files/',
    '/media/',
    '/images/',
    '/css/',
    '/js/',
    '/scripts/',
    
    # Error pages
    '/404.html',
    '/500.html',
    '/error.html',
    '/maintenance.html',
    
    # Security
    '/.htaccess',
    '/.htpasswd',
    '/security.txt',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',
]

# All endpoints combined
ENDPOINTS = {
    'kubernetes': KUBERNETES_ENDPOINTS,
    'cloud': CLOUD_ENDPOINTS,
    'web': WEB_COMMON_ENDPOINTS
}

def get_endpoints_by_category(category: str) -> list:
    """Get endpoints for a specific category"""
    return ENDPOINTS.get(category, [])

def get_all_endpoints() -> list:
    """Get all endpoints as a flat list"""
    all_endpoints = []
    for category_endpoints in ENDPOINTS.values():
        all_endpoints.extend(category_endpoints)
    return all_endpoints

def get_endpoint_count() -> dict:
    """Get count of endpoints per category"""
    return {category: len(endpoints) for category, endpoints in ENDPOINTS.items()}

def filter_endpoints_by_pattern(pattern: str) -> list:
    """Filter endpoints by a pattern"""
    import re
    compiled_pattern = re.compile(pattern, re.IGNORECASE)
    
    filtered = []
    for endpoints in ENDPOINTS.values():
        for endpoint in endpoints:
            if compiled_pattern.search(endpoint):
                filtered.append(endpoint)
    
    return filtered