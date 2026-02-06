# Gunicorn Production Configuration for SIGIL Web
# ================================================

import os

# Bind to localhost only (Tor will proxy)
bind = "127.0.0.1:5000"

# Workers - for Pi, keep it low
workers = 1
worker_class = "sync"
threads = 1

# Timeouts - SE050 operations can be slow
timeout = 120
graceful_timeout = 30
keepalive = 5

# Security
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190

# Logging
accesslog = "/var/log/sigil/access.log"
errorlog = "/var/log/sigil/error.log"
loglevel = "warning"
capture_output = True

# Process naming
proc_name = "sigil-web"

# Don't daemonize - let systemd handle it
daemon = False

# Preload app for faster worker spawning
preload_app = True

# Restart workers periodically to prevent memory leaks
max_requests = 1000
max_requests_jitter = 100
