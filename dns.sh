#!/bin/bash
# FilterDNS - Complete Setup Script
# This script finalizes the DNS filtering server setup and prepares the web interface

# Text formatting
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
  echo -e "${BOLD}${GREEN}[+] $1${NC}"
}

# Function to print warning messages
print_warning() {
  echo -e "${BOLD}${YELLOW}[!] $1${NC}"
}

# Function to print error messages
print_error() {
  echo -e "${BOLD}${RED}[-] $1${NC}"
}

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  print_error "Please run as root"
  exit 1
fi

print_status "Starting FilterDNS complete setup..."

# Create all necessary directories
print_status "Creating directory structure..."
mkdir -p /opt/filterdns/bin
mkdir -p /opt/filterdns/conf
mkdir -p /opt/filterdns/data/blocklists
mkdir -p /opt/filterdns/data/stats
mkdir -p /opt/filterdns/data/zones
mkdir -p /opt/filterdns/logs
mkdir -p /opt/filterdns/web
mkdir -p /var/log/named

# Fix BIND configuration
print_status "Fixing BIND configuration..."

# Update named.conf.options
cat > /etc/bind/named.conf.options << EOF
options {
  directory "/var/cache/bind";
  
  // Forward DNS queries to these servers if we don't have the answer
  forwarders {
      1.1.1.1;     // Cloudflare
      8.8.8.8;     // Google
      9.9.9.9;     // Quad9
  };
  
  // Response Policy Zone for content filtering
  response-policy {
      zone "rpz.filterdns.local";
  };
  
  // If DNSSEC validation fails, return SERVFAIL
  dnssec-validation auto;
  
  // Listen on all interfaces
  listen-on { any; };
  listen-on-v6 { any; };
  
  // Allow queries from any IP
  allow-query { any; };
  
  // Disable recursive queries from external sources
  allow-recursion { localnets; localhost; };
  
  // Disable zone transfers
  allow-transfer { none; };
  
  // Enable query logging for statistics
  querylog yes;
  
  // Performance tuning
  max-cache-size 256M;
  
  // Security settings
  version "DNS Server";
  
  // Prevent DNS rebinding attacks
  empty-zones-enable yes;
};
EOF

# Update named.conf.local
cat > /etc/bind/named.conf.local << EOF
// Response Policy Zone for content filtering
zone "rpz.filterdns.local" {
  type master;
  file "/etc/bind/db.rpz.filterdns.local";
  allow-query { none; };
};

// Local zone for internal use
zone "filterdns.local" {
  type master;
  file "/etc/bind/db.filterdns.local";
  allow-query { any; };
};
EOF

# Create RPZ zone file
cat > /etc/bind/db.rpz.filterdns.local << EOF
\$TTL 60
@            IN    SOA  localhost. root.localhost. (
                        $(date +%Y%m%d01) ; serial
                        1h         ; refresh
                        30m        ; retry
                        1w         ; expiry
                        1h         ; minimum
                       )
           IN    NS   localhost.

; Example blocked domains
example.com        CNAME .
example.net        CNAME .
example.org        CNAME .
EOF

# Create local zone file
cat > /etc/bind/db.filterdns.local << EOF
\$TTL 86400
@            IN    SOA  filterdns.local. admin.filterdns.local. (
                        $(date +%Y%m%d01) ; serial
                        1d         ; refresh
                        2h         ; retry
                        1w         ; expiry
                        1d         ; minimum
                       )
           IN    NS   localhost.
           IN    A    127.0.0.1

; Add local DNS entries below
www          IN    A    127.0.0.1
admin        IN    A    127.0.0.1
EOF

# Set proper permissions
chown bind:bind /etc/bind/db.rpz.filterdns.local
chown bind:bind /etc/bind/db.filterdns.local

# Create enhanced blocklist update script
print_status "Creating enhanced blocklist update script..."
cat > /opt/filterdns/bin/update-blocklists.sh << 'EOF'
#!/bin/bash
# FilterDNS Blocklist Update Script
# This script downloads and processes blocklists for DNS filtering

# Configuration
BLOCKLIST_DIR="/opt/filterdns/data/blocklists"
ZONE_FILE="/etc/bind/db.rpz.filterdns.local"
LOG_FILE="/opt/filterdns/logs/blocklist-update.log"
TEMP_DIR=$(mktemp -d)
CATEGORIES=(
  "adult"
  "malware"
  "ads"
  "tracking"
)

# Blocklist URLs
declare -A BLOCKLIST_URLS
BLOCKLIST_URLS[adult]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts"
BLOCKLIST_URLS[malware]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-malware/hosts"
BLOCKLIST_URLS[ads]="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts"
BLOCKLIST_URLS[tracking]="https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt"

# Start logging
mkdir -p $(dirname "$LOG_FILE")
echo "=== FilterDNS Blocklist Update $(date) ===" > "$LOG_FILE"

# Create directory structure if it doesn't exist
mkdir -p "$BLOCKLIST_DIR"
for category in "${CATEGORIES[@]}"; do
  mkdir -p "$BLOCKLIST_DIR/$category"
done

# Create zone file header
cat > "$ZONE_FILE" << HEADER
\$TTL 60
@            IN    SOA  localhost. root.localhost. (
                        $(date +%Y%m%d01) ; serial
                        1h         ; refresh
                        30m        ; retry
                        1w         ; expiry
                        1h         ; minimum
                       )
           IN    NS   localhost.

; This file is automatically generated by the update-blocklists.sh script
; Last updated: $(date)

HEADER

# Process each category
for category in "${CATEGORIES[@]}"; do
  echo "Processing category: $category" >> "$LOG_FILE"
  
  # Check if category is enabled
  if [ -f "$BLOCKLIST_DIR/$category/disabled" ]; then
      echo "Category $category is disabled, skipping" >> "$LOG_FILE"
      continue
  fi
  
  # Download blocklist
  echo "Downloading blocklist for $category..." >> "$LOG_FILE"
  BLOCKLIST_URL="${BLOCKLIST_URLS[$category]}"
  DOWNLOAD_FILE="$TEMP_DIR/$category.txt"
  
  if curl -s -o "$DOWNLOAD_FILE" "$BLOCKLIST_URL"; then
      echo "Download successful" >> "$LOG_FILE"
  else
      echo "Download failed for $category" >> "$LOG_FILE"
      continue
  fi
  
  # Process blocklist to extract domains
  echo "Extracting domains from blocklist..." >> "$LOG_FILE"
  DOMAINS_FILE="$TEMP_DIR/$category.domains"
  
  # Extract domains from hosts file format
  grep -v "#" "$DOWNLOAD_FILE" | grep -v "localhost" | grep -v "::1" | \
      sed -E 's/^([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+//' | \
      grep -E '^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$' | \
      sort | uniq > "$DOMAINS_FILE"
  
  # Count domains
  DOMAIN_COUNT=$(wc -l < "$DOMAINS_FILE")
  echo "Extracted $DOMAIN_COUNT domains for category $category" >> "$LOG_FILE"
  
  # Save processed domains for reference
  cp "$DOMAINS_FILE" "$BLOCKLIST_DIR/$category/domains.txt"
  
  # Add to RPZ zone file with category comment
  echo "; Category: $category - $DOMAIN_COUNT domains" >> "$ZONE_FILE"
  while read -r domain; do
      echo "$domain        CNAME ." >> "$ZONE_FILE"
  done < "$DOMAINS_FILE"
  echo "" >> "$ZONE_FILE"
done

# Add custom blocklist if it exists
CUSTOM_BLOCKLIST="$BLOCKLIST_DIR/custom.txt"
if [ -f "$CUSTOM_BLOCKLIST" ]; then
  echo "Adding custom blocklist entries..." >> "$LOG_FILE"
  echo "; Custom blocklist entries" >> "$ZONE_FILE"
  while read -r domain; do
      # Skip comments and empty lines
      [[ "$domain" =~ ^#.*$ || -z "$domain" ]] && continue
      echo "$domain        CNAME ." >> "$ZONE_FILE"
  done < "$CUSTOM_BLOCKLIST"
  echo "" >> "$ZONE_FILE"
fi

# Add whitelist (domains that should never be blocked)
WHITELIST="$BLOCKLIST_DIR/whitelist.txt"
if [ -f "$WHITELIST" ]; then
  echo "Processing whitelist..." >> "$LOG_FILE"
  echo "; Whitelist entries (PASSTHRU)" >> "$ZONE_FILE"
  while read -r domain; do
      # Skip comments and empty lines
      [[ "$domain" =~ ^#.*$ || -z "$domain" ]] && continue
      echo "$domain        CNAME rpz-passthru." >> "$ZONE_FILE"
  done < "$WHITELIST"
fi

# Clean up
rm -rf "$TEMP_DIR"

# Set proper permissions
chown bind:bind "$ZONE_FILE"

# Reload BIND configuration
echo "Reloading BIND configuration..." >> "$LOG_FILE"
rndc reload

# Update statistics
TOTAL_DOMAINS=$(grep -c "CNAME \." "$ZONE_FILE" || echo "0")
WHITELIST_DOMAINS=$(grep -c "CNAME rpz-passthru" "$ZONE_FILE" || echo "0")
echo "Total blocked domains: $TOTAL_DOMAINS" >> "$LOG_FILE"
echo "Whitelist domains: $WHITELIST_DOMAINS" >> "$LOG_FILE"

# Save statistics for the web interface
STATS_FILE="/opt/filterdns/data/stats/blocklist_stats.json"
mkdir -p $(dirname "$STATS_FILE")
cat > "$STATS_FILE" << STATS
{
  "last_update": "$(date +%s)",
  "last_update_formatted": "$(date)",
  "total_domains": $TOTAL_DOMAINS,
  "whitelist_domains": $WHITELIST_DOMAINS,
  "categories": {
STATS

# Add category statistics
first=true
for category in "${CATEGORIES[@]}"; do
  if [ -f "$BLOCKLIST_DIR/$category/domains.txt" ]; then
      count=$(wc -l < "$BLOCKLIST_DIR/$category/domains.txt" || echo "0")
      if [ "$first" = true ]; then
          first=false
      else
          echo "," >> "$STATS_FILE"
      fi
      echo "    \"$category\": {" >> "$STATS_FILE"
      echo "      \"count\": $count," >> "$STATS_FILE"
      echo "      \"enabled\": $([ -f "$BLOCKLIST_DIR/$category/disabled" ] && echo "false" || echo "true")" >> "$STATS_FILE"
      echo -n "    }" >> "$STATS_FILE"
  fi
done

cat >> "$STATS_FILE" << STATS

  }
}
STATS

echo "Blocklist update completed at $(date)" >> "$LOG_FILE"
echo "=================================================" >> "$LOG_FILE"
EOF

# Make the script executable
chmod +x /opt/filterdns/bin/update-blocklists.sh

# Create DNS query logging script
print_status "Creating DNS query logging script..."
cat > /opt/filterdns/bin/log-dns-queries.sh << 'EOF'
#!/bin/bash
# FilterDNS Query Logging Script
# This script processes BIND query logs and generates statistics

LOG_DIR="/var/log/named"
STATS_DIR="/opt/filterdns/data/stats"
TEMP_DIR=$(mktemp -d)
ZONE_FILE="/etc/bind/db.rpz.filterdns.local"

# Create stats directory if it doesn't exist
mkdir -p "$STATS_DIR"

# Get current timestamp
TIMESTAMP=$(date +%s)
DATE_FORMATTED=$(date)

# Process query log to extract statistics
echo "Processing DNS query logs at $DATE_FORMATTED"

# Count total queries in the last hour
TOTAL_QUERIES=$(grep -c "query:" "$LOG_DIR/query.log" 2>/dev/null || echo "0")

# Count blocked queries (NXDOMAIN responses for RPZ)
BLOCKED_QUERIES=$(grep "rpz.*NXDOMAIN" "$LOG_DIR/query.log" 2>/dev/null | wc -l || echo "0")

# Extract top queried domains
grep "query:" "$LOG_DIR/query.log" 2>/dev/null | \
  awk '{print $6}' | sort | uniq -c | sort -nr | \
  head -20 > "$TEMP_DIR/top_domains.txt"

# Extract top blocked domains
grep "rpz.*NXDOMAIN" "$LOG_DIR/query.log" 2>/dev/null | \
  awk '{print $6}' | sort | uniq -c | sort -nr | \
  head -20 > "$TEMP_DIR/top_blocked.txt"

# Extract unique client IPs
grep "client" "$LOG_DIR/query.log" 2>/dev/null | \
  awk '{print $4}' | sed 's/#.*$//' | sort | uniq | \
  wc -l > "$TEMP_DIR/unique_clients.txt"

# Generate JSON statistics file
cat > "$STATS_DIR/query_stats.json" << EOF2
{
"timestamp": $TIMESTAMP,
"date_formatted": "$DATE_FORMATTED",
"total_queries": $TOTAL_QUERIES,
"blocked_queries": $BLOCKED_QUERIES,
"unique_clients": $(cat "$TEMP_DIR/unique_clients.txt" || echo "0"),
"top_domains": [
EOF2

# Add top domains to JSON
first=true
while read -r line; do
  count=$(echo "$line" | awk '{print $1}')
  domain=$(echo "$line" | awk '{print $2}')
  if [ "$first" = true ]; then
      first=false
  else
      echo "," >> "$STATS_DIR/query_stats.json"
  fi
  echo "    { \"domain\": \"$domain\", \"count\": $count }" >> "$STATS_DIR/query_stats.json"
done < "$TEMP_DIR/top_domains.txt"

cat >> "$STATS_DIR/query_stats.json" << EOF2
],
"top_blocked": [
EOF2

# Add top blocked domains to JSON
first=true
while read -r line; do
  count=$(echo "$line" | awk '{print $1}')
  domain=$(echo "$line" | awk '{print $2}')
  if [ "$first" = true ]; then
      first=false
  else
      echo "," >> "$STATS_DIR/query_stats.json"
  fi
  echo "    { \"domain\": \"$domain\", \"count\": $count }" >> "$STATS_DIR/query_stats.json"
done < "$TEMP_DIR/top_blocked.txt"

cat >> "$STATS_DIR/query_stats.json" << EOF2
]
}
EOF2

# Clean up
rm -rf "$TEMP_DIR"

# Rotate query log if it's getting too large
if [ -f "$LOG_DIR/query.log" ] && [ $(stat -c%s "$LOG_DIR/query.log" 2>/dev/null || echo "0") -gt 10485760 ]; then
  echo "Rotating query log file..."
  mv "$LOG_DIR/query.log" "$LOG_DIR/query.log.1"
  kill -HUP $(pidof named)
fi

echo "DNS query statistics updated at $DATE_FORMATTED"
EOF

# Make the script executable
chmod +x /opt/filterdns/bin/log-dns-queries.sh

# Create DNS server control script
print_status "Creating DNS server control script..."
cat > /opt/filterdns/bin/dns-control.sh << 'EOF'
#!/bin/bash
# FilterDNS Control Script
# This script provides functions to control the DNS server

# Usage information
usage() {
  echo "Usage: $0 [command]"
  echo
  echo "Commands:"
  echo "  status        - Show DNS server status"
  echo "  start         - Start DNS server"
  echo "  stop          - Stop DNS server"
  echo "  restart       - Restart DNS server"
  echo "  reload        - Reload DNS configuration"
  echo "  update        - Update blocklists"
  echo "  enable [cat]  - Enable a category (adult, malware, ads, tracking)"
  echo "  disable [cat] - Disable a category (adult, malware, ads, tracking)"
  echo "  stats         - Show DNS server statistics"
  echo "  help          - Show this help message"
  echo
}

# Check if BIND is running
check_status() {
  if systemctl is-active --quiet bind9; then
      echo "DNS server is running"
      return 0
  else
      echo "DNS server is not running"
      return 1
  fi
}

# Start BIND
start_server() {
  echo "Starting DNS server..."
  systemctl start bind9
  if check_status; then
      echo "DNS server started successfully"
  else
      echo "Failed to start DNS server"
  fi
}

# Stop BIND
stop_server() {
  echo "Stopping DNS server..."
  systemctl stop bind9
  if ! check_status; then
      echo "DNS server stopped successfully"
  else
      echo "Failed to stop DNS server"
  fi
}

# Restart BIND
restart_server() {
  echo "Restarting DNS server..."
  systemctl restart bind9
  if check_status; then
      echo "DNS server restarted successfully"
  else
      echo "Failed to restart DNS server"
  fi
}

# Reload BIND configuration
reload_config() {
  echo "Reloading DNS configuration..."
  rndc reload
  echo "DNS configuration reloaded"
}

# Update blocklists
update_blocklists() {
  echo "Updating blocklists..."
  /opt/filterdns/bin/update-blocklists.sh
}

# Enable a category
enable_category() {
  if [ -z "$1" ]; then
      echo "Error: No category specified"
      echo "Available categories: adult, malware, ads, tracking"
      return 1
  fi
  
  category="$1"
  case "$category" in
      adult|malware|ads|tracking)
          echo "Enabling category: $category"
          rm -f "/opt/filterdns/data/blocklists/$category/disabled"
          update_blocklists
          ;;
      *)
          echo "Error: Invalid category '$category'"
          echo "Available categories: adult, malware, ads, tracking"
          return 1
          ;;
  esac
}

# Disable a category
disable_category() {
  if [ -z "$1" ]; then
      echo "Error: No category specified"
      echo "Available categories: adult, malware, ads, tracking"
      return 1
  fi
  
  category="$1"
  case "$category" in
      adult|malware|ads|tracking)
          echo "Disabling category: $category"
          touch "/opt/filterdns/data/blocklists/$category/disabled"
          update_blocklists
          ;;
      *)
          echo "Error: Invalid category '$category'"
          echo "Available categories: adult, malware, ads, tracking"
          return 1
          ;;
  esac
}

# Show DNS server statistics
show_stats() {
  echo "DNS Server Statistics"
  echo "====================="
  
  # Check if statistics files exist
  if [ -f "/opt/filterdns/data/stats/blocklist_stats.json" ]; then
      echo "Blocklist Statistics:"
      echo "  Last Update: $(jq -r '.last_update_formatted' /opt/filterdns/data/stats/blocklist_stats.json 2>/dev/null || echo "Unknown")"
      echo "  Total Blocked Domains: $(jq -r '.total_domains' /opt/filterdns/data/stats/blocklist_stats.json 2>/dev/null || echo "Unknown")"
      echo "  Whitelist Domains: $(jq -r '.whitelist_domains' /opt/filterdns/data/stats/blocklist_stats.json 2>/dev/null || echo "Unknown")"
      echo
      echo "  Categories:"
      for category in adult malware ads tracking; do
          if jq -e ".categories.$category" /opt/filterdns/data/stats/blocklist_stats.json > /dev/null 2>&1; then
              count=$(jq -r ".categories.$category.count" /opt/filterdns/data/stats/blocklist_stats.json)
              enabled=$(jq -r ".categories.$category.enabled" /opt/filterdns/data/stats/blocklist_stats.json)
              echo "    - $category: $count domains ($([ "$enabled" = "true" ] && echo "Enabled" || echo "Disabled"))"
          fi
      done
  else
      echo "No blocklist statistics available. Run 'update' command first."
  fi
  
  echo
  echo "Server Status:"
  systemctl status bind9 | grep "Active:"
  
  echo
  echo "Query Statistics:"
  if [ -f "/opt/filterdns/data/stats/query_stats.json" ]; then
      echo "  Last Update: $(jq -r '.date_formatted' /opt/filterdns/data/stats/query_stats.json 2>/dev/null || echo "Unknown")"
      echo "  Total Queries: $(jq -r '.total_queries' /opt/filterdns/data/stats/query_stats.json 2>/dev/null || echo "Unknown")"
      echo "  Blocked Queries: $(jq -r '.blocked_queries' /opt/filterdns/data/stats/query_stats.json 2>/dev/null || echo "Unknown")"
      echo "  Unique Clients: $(jq -r '.unique_clients' /opt/filterdns/data/stats/query_stats.json 2>/dev/null || echo "Unknown")"
      
      echo
      echo "  Top 5 Queried Domains:"
      jq -r '.top_domains | .[:5] | .[] | "    - \(.domain): \(.count) queries"' /opt/filterdns/data/stats/query_stats.json 2>/dev/null || echo "    No data available"
      
      echo
      echo "  Top 5 Blocked Domains:"
      jq -r '.top_blocked | .[:5] | .[] | "    - \(.domain): \(.count) blocks"' /opt/filterdns/data/stats/query_stats.json 2>/dev/null || echo "    No data available"
  else
      echo "No query statistics available."
  fi
}

# Main command processing
case "$1" in
  status)
      check_status
      ;;
  start)
      start_server
      ;;
  stop)
      stop_server
      ;;
  restart)
      restart_server
      ;;
  reload)
      reload_config
      ;;
  update)
      update_blocklists
      ;;
  enable)
      enable_category "$2"
      ;;
  disable)
      disable_category "$2"
      ;;
  stats)
      show_stats
      ;;
  help|--help|-h)
      usage
      ;;
  *)
      echo "Error: Unknown command '$1'"
      usage
      exit 1
      ;;
esac
EOF

# Make the script executable
chmod +x /opt/filterdns/bin/dns-control.sh

# Create a simple API server for the web interface
print_status "Creating API server for web interface..."
cat > /opt/filterdns/bin/api-server.py << 'EOF'
#!/usr/bin/env python3
# FilterDNS API Server
# This script provides a simple API for the web interface to interact with the DNS server

import http.server
import socketserver
import json
import os
import subprocess
import time
from urllib.parse import urlparse, parse_qs

# Configuration
PORT = 8080
BASE_DIR = "/opt/filterdns"
DATA_DIR = f"{BASE_DIR}/data"
BIN_DIR = f"{BASE_DIR}/bin"
STATS_DIR = f"{DATA_DIR}/stats"
BLOCKLIST_DIR = f"{DATA_DIR}/blocklists"

class FilterDNSHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Parse URL
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # Set CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        
        # API endpoints
        if path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Get DNS server status
            try:
                result = subprocess.run(['systemctl', 'is-active', 'bind9'], 
                                       capture_output=True, text=True)
                status = result.stdout.strip()
                
                # Get uptime if running
                uptime = "N/A"
                if status == "active":
                    result = subprocess.run(['systemctl', 'show', 'bind9', '--property=ActiveEnterTimestamp'], 
                                           capture_output=True, text=True)
                    if result.stdout:
                        timestamp = result.stdout.split('=')[1].strip()
                        uptime = f"Since {timestamp}"
                
                response = {
                    'status': status,
                    'uptime': uptime,
                    'timestamp': int(time.time())
                }
                
                self.wfile.write(json.dumps(response).encode())
            except Exception as e:
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        
        elif path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Combine statistics from different sources
            response = {
                'timestamp': int(time.time()),
                'server': {},
                'blocklists': {},
                'queries': {}
            }
            
            # Load blocklist stats if available
            blocklist_stats_file = f"{STATS_DIR}/blocklist_stats.json"
            if os.path.exists(blocklist_stats_file):
                with open(blocklist_stats_file, 'r') as f:
                    response['blocklists'] = json.load(f)
            
            # Load query stats if available
            query_stats_file = f"{STATS_DIR}/query_stats.json"
            if os.path.exists(query_stats_file):
                with open(query_stats_file, 'r') as f:
                    response['queries'] = json.load(f)
            
            # Get server info
            try:
                # Get DNS server version
                result = subprocess.run(['named', '-v'], 
                                       capture_output=True, text=True)
                response['server']['version'] = result.stdout.strip()
                
                # Get system info
                with open('/proc/loadavg', 'r') as f:
                    load = f.read().strip().split()
                    response['server']['load'] = {
                        '1min': float(load[0]),
                        '5min': float(load[1]),
                        '15min': float(load[2])
                    }
                
                # Get memory info
                result = subprocess.run(['free', '-m'], 
                                       capture_output=True, text=True)
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    mem_info = lines[1].split()
                    response['server']['memory'] = {
                        'total': int(mem_info[1]),
                        'used': int(mem_info[2]),
                        'free': int(mem_info[3])
                    }
            except Exception as e:
                response['server']['error'] = str(e)
            
            self.wfile.write(json.dumps(response).encode())
        
        elif path == '/api/config':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Get configuration information
            config = {
                'categories': {}
            }
            
            # Check which categories are enabled
            for category in ['adult', 'malware', 'ads', 'tracking']:
                category_dir = f"{BLOCKLIST_DIR}/{category}"
                if os.path.exists(category_dir):
                    disabled = os.path.exists(f"{category_dir}/disabled")
                    count = 0
                    domains_file = f"{category_dir}/domains.txt"
                    if os.path.exists(domains_file):
                        with open(domains_file, 'r') as f:
                            count = sum(1 for _ in f)
                    
                    config['categories'][category] = {
                        'enabled': not disabled,
                        'count': count
                    }
            
            # Get custom blocklist and whitelist info
            custom_file = f"{BLOCKLIST_DIR}/custom.txt"
            whitelist_file = f"{BLOCKLIST_DIR}/whitelist.txt"
            
            custom_count = 0
            if os.path.exists(custom_file):
                with open(custom_file, 'r') as f:
                    custom_count = sum(1 for line in f if line.strip() and not line.startswith('#'))
            
            whitelist_count = 0
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r') as f:
                    whitelist_count = sum(1 for line in f if line.strip() and not line.startswith('#'))
            
            config['custom'] = {
                'count': custom_count
            }
            
            config['whitelist'] = {
                'count': whitelist_count
            }
            
            self.wfile.write(json.dumps(config).encode())
        
        else:
            # Serve static files from web directory
            if path == '/':
                path = '/index.html'
            
            file_path = f"{BASE_DIR}/web{path}"
            
            if os.path.exists(file_path) and os.path.isfile(file_path):
                self.send_response(200)
                
                # Set content type based on file extension
                if path.endswith('.html'):
                    self.send_header('Content-type', 'text/html')
                elif path.endswith('.js'):
                    self.send_header('Content-type', 'application/javascript')
                elif path.endswith('.css'):
                    self.send_header('Content-type', 'text/css')
                elif path.endswith('.json'):
                    self.send_header('Content-type', 'application/json')
                elif path.endswith('.png'):
                    self.send_header('Content-type', 'image/png')
                elif path.endswith('.jpg') or path.endswith('.jpeg'):
                    self.send_header('Content-type', 'image/jpeg')
                else:
                    self.send_header('Content-type', 'text/plain')
                
                self.end_headers()
                
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'File not found')
    
    def do_POST(self):
        # Parse URL
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # Set CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        
        # Read request body
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(post_data)
        except:
            data = {}
        
        # API endpoints
        if path == '/api/control':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            action = data.get('action', '')
            
            if action == 'start':
                result = subprocess.run([f"{BIN_DIR}/dns-control.sh", "start"], 
                                       capture_output=True, text=True)
                response = {
                    'success': True,
                    'message': result.stdout.strip(),
                    'action': action
                }
            
            elif action == 'stop':
                result = subprocess.run([f"{BIN_DIR}/dns-control.sh", "stop"], 
                                       capture_output=True, text=True)
                response = {
                    'success': True,
                    'message': result.stdout.strip(),
                    'action': action
                }
            
            elif action == 'restart':
                result = subprocess.run([f"{BIN_DIR}/dns-control.sh", "restart"], 
                                       capture_output=True, text=True)
                response = {
                    'success': True,
                    'message': result.stdout.strip(),
                    'action': action
                }
            
            elif action == 'update':
                result = subprocess.run([f"{BIN_DIR}/dns-control.sh", "update"], 
                                       capture_output=True, text=True)
                response = {
                    'success': True,
                    'message': "Blocklists updated successfully",
                    'action': action
                }
            
            elif action == 'enable_category':
                category = data.get('category', '')
                if category in ['adult', 'malware', 'ads', 'tracking']:
                    result = subprocess.run([f"{BIN_DIR}/dns-control.sh", "enable", category], 
                                           capture_output=True, text=True)
                    response = {
                        'success': True,
                        'message': f"Category '{category}' enabled",
                        'action': action,
                        'category': category
                    }
                else:
                    response = {
                        'success': False,
                        'message': f"Invalid category: {category}",
                        'action': action
                    }
            
            elif action == 'disable_category':
                category = data.get('category', '')
                if category in ['adult', 'malware', 'ads', 'tracking']:
                    result = subprocess.run([f"{BIN_DIR}/dns-control.sh", "disable", category], 
                                           capture_output=True, text=True)
                    response = {
                        'success': True,
                        'message': f"Category '{category}' disabled",
                        'action': action,
                        'category': category
                    }
                else:
                    response = {
                        'success': False,
                        'message': f"Invalid category: {category}",
                        'action': action
                    }
            
            elif action == 'update_custom':
                custom_domains = data.get('domains', [])
                
                with open(f"{BLOCKLIST_DIR}/custom.txt", 'w') as f:
                    f.write("# Custom blocklist - Updated at " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
                    for domain in custom_domains:
                        f.write(domain + "\n")
                
                # Update blocklists
                subprocess.run([f"{BIN_DIR}/dns-control.sh", "update"], 
                              capture_output=True, text=True)
                
                response = {
                    'success': True,
                    'message': f"Custom blocklist updated with {len(custom_domains)} domains",
                    'action': action
                }
            
            elif action == 'update_whitelist':
                whitelist_domains = data.get('domains', [])
                
                with open(f"{BLOCKLIST_DIR}/whitelist.txt", 'w') as f:
                    f.write("# Whitelist - Updated at " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
                    for domain in whitelist_domains:
                        f.write(domain + "\n")
                
                # Update blocklists
                subprocess.run([f"{BIN_DIR}/dns-control.sh", "update"], 
                              capture_output=True, text=True)
                
                response = {
                    'success': True,
                    'message': f"Whitelist updated with {len(whitelist_domains)} domains",
                    'action': action
                }
            
            else:
                response = {
                    'success': False,
                    'message': f"Unknown action: {action}",
                    'action': action
                }
            
            self.wfile.write(json.dumps(response).encode())
        
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Endpoint not found')
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run_server():
    with socketserver.TCPServer(("", PORT), FilterDNSHandler) as httpd:
        print(f"API server running at http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
EOF

# Make the script executable
chmod +x /opt/filterdns/bin/api-server.py

# Create a simple index.html for the web interface
print_status "Creating web interface..."
cat > /opt/filterdns/web/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FilterDNS - DNS Filtering Server</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: #2c3e50;
            color: white;
            padding: 1rem;
            text-align: center;
        }
        
        h1 {
            margin: 0;
        }
        
        .status-card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 5px;
        }
        
        .status-running {
            background-color: #2ecc71;
        }
        
        .status-stopped {
            background-color: #e74c3c;
        }
        
        .card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
        }
        
        .card h3 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        
        .button {
            display: inline-block;
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin-right: 10px;
        }
        
        .button:hover {
            background-color: #2980b9;
        }
        
        .button-danger {
            background-color: #e74c3c;
        }
        
        .button-danger:hover {
            background-color: #c0392b;
        }
        
        .button-success {
            background-color: #2ecc71;
        }
        
        .button-success:hover {
            background-color: #27ae60;
        }
        
        .toggle-switch {
            position: relative;
            display: inline-block;
            width: 60px;
            height: 34px;
        }
        
        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 34px;
        }
        
        .slider:before {
            position: absolute;
            content: "";
            height: 26px;
            width: 26px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        
        input:checked + .slider {
            background-color: #2ecc71;
        }
        
        input:checked + .slider:before {
            transform: translateX(26px);
        }
        
        .category-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }
        
        .category-item:last-child {
            border-bottom: none;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            font-style: italic;
            color: #7f8c8d;
        }
        
        .stats-value {
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stats-label {
            color: #7f8c8d;
            font-size: 14px;
        }
        
        .domain-list {
            max-height: 200px;
            overflow-y: auto;
            margin-top: 10px;
        }
        
        .domain-item {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #f5f5f5;
        }
        
        footer {
            text-align: center;
            padding: 20px;
            background-color: #2c3e50;
            color: white;
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <header>
        <h1>FilterDNS Server</h1>
        <p>DNS Filtering Server Management Interface</p>
    </header>
    
    <div class="container">
        <div id="status-card" class="status-card">
            <h2>Server Status</h2>
            <div id="status-indicator">
                <div class="loading">Loading server status...</div>
            </div>
            <div id="server-controls" style="margin-top: 20px;">
                <button id="start-button" class="button button-success">Start Server</button>
                <button id="stop-button" class="button button-danger">Stop Server</button>
                <button id="restart-button" class="button">Restart Server</button>
                <button id="update-button" class="button">Update Blocklists</button>
            </div>
        </div>
        
        <div class="card-grid">
            <div class="card">
                <h3>DNS Query Statistics</h3>
                <div id="query-stats">
                    <div class="loading">Loading statistics...</div>
                </div>
            </div>
            
            <div class="card">
                <h3>Blocklist Statistics</h3>
                <div id="blocklist-stats">
                    <div class="loading">Loading statistics...</div>
                </div>
            </div>
            
            <div class="card">
                <h3>System Information</h3>
                <div id="system-info">
                    <div class="loading">Loading system information...</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>Content Filtering Categories</h3>
            <div id="categories">
                <div class="loading">Loading categories...</div>
            </div>
        </div>
        
        <div class="card-grid">
            <div class="card">
                <h3>Top Queried Domains</h3>
                <div id="top-domains">
                    <div class="loading">Loading domain statistics...</div>
                </div>
            </div>
            
            <div class="card">
                <h3>Top Blocked Domains</h3>
                <div id="top-blocked">
                    <div class="loading">Loading domain statistics...</div>
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        <p>FilterDNS Server &copy; 2025 | <a href="#" style="color: white;">Documentation</a></p>
    </footer>
    
    <script>
        // API endpoint
        const API_BASE = '';
        
        // Function to fetch data from API
        async function fetchAPI(endpoint) {
            try {
                const response = await fetch(`${API_BASE}${endpoint}`);
                return await response.json();
            } catch (error) {
                console.error(`Error fetching ${endpoint}:`, error);
                return null;
            }
        }
        
        // Function to post data to API
        async function postAPI(endpoint, data) {
            try {
                const response = await fetch(`${API_BASE}${endpoint}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });
                return await response.json();
            } catch (error) {
                console.error(`Error posting to ${endpoint}:`, error);
                return null;
            }
        }
        
        // Function to update server status
        async function updateServerStatus() {
            const statusIndicator = document.getElementById('status-indicator');
            const data = await fetchAPI('/api/status');
            
            if (data) {
                let statusHTML = '';
                if (data.status === 'active') {
                    statusHTML = `
                        <p><span class="status-indicator status-running"></span> DNS Server is <strong>running</strong></p>
                        <p>Uptime: ${data.uptime}</p>
                    `;
                } else {
                    statusHTML = `
                        <p><span class="status-indicator status-stopped"></span> DNS Server is <strong>stopped</strong></p>
                    `;
                }
                statusIndicator.innerHTML = statusHTML;
            } else {
                statusIndicator.innerHTML = '<p>Error fetching server status</p>';
            }
        }
        
        // Function to update statistics
        async function updateStatistics() {
            const queryStats = document.getElementById('query-stats');
            const blocklistStats = document.getElementById('blocklist-stats');
            const systemInfo = document.getElementById('system-info');
            const topDomains = document.getElementById('top-domains');
            const topBlocked = document.getElementById('top-blocked');
            
            const data = await fetchAPI('/api/stats');
            
            if (data) {
                // Query statistics
                if (data.queries && data.queries.total_queries !== undefined) {
                    queryStats.innerHTML = `
                        <div class="stats-value">${data.queries.total_queries.toLocaleString()}</div>
                        <div class="stats-label">Total DNS Queries</div>
                        <div class="stats-value">${data.queries.blocked_queries.toLocaleString()}</div>
                        <div class="stats-label">Blocked Queries</div>
                        <div class="stats-value">${data.queries.unique_clients.toLocaleString()}</div>
                        <div class="stats-label">Unique Clients</div>
                        <div class="stats-label">Last Updated: ${data.queries.date_formatted}</div>
                    `;
                } else {
                    queryStats.innerHTML = '<p>No query statistics available</p>';
                }
                
                // Blocklist statistics
                if (data.blocklists && data.blocklists.total_domains !== undefined) {
                    blocklistStats.innerHTML = `
                        <div class="stats-value">${data.blocklists.total_domains.toLocaleString()}</div>
                        <div class="stats-label">Total Blocked Domains</div>
                        <div class="stats-value">${data.blocklists.whitelist_domains.toLocaleString()}</div>
                        <div class="stats-label">Whitelist Domains</div>
                        <div class="stats-label">Last Updated: ${data.blocklists.last_update_formatted}</div>
                    `;
                } else {
                    blocklistStats.innerHTML = '<p>No blocklist statistics available</p>';
                }
                
                // System information
                if (data.server) {
                    let systemHTML = '';
                    
                    if (data.server.version) {
                        systemHTML += `<p><strong>DNS Server:</strong> ${data.server.version}</p>`;
                    }
                    
                    if (data.server.load) {
                        systemHTML += `<p><strong>System Load:</strong> ${data.server.load['1min']} (1m), ${data.server.load['5min']} (5m), ${data.server.load['15min']} (15m)</p>`;
                    }
                    
                    if (data.server.memory) {
                        const memoryUsedPercent = Math.round((data.server.memory.used / data.server.memory.total) * 100);
                        systemHTML += `<p><strong>Memory Usage:</strong> ${data.server.memory.used} MB / ${data.server.memory.total} MB (${memoryUsedPercent}%)</p>`;
                    }
                    
                    systemInfo.innerHTML = systemHTML || '<p>No system information available</p>';
                } else {
                    systemInfo.innerHTML = '<p>No system information available</p>';
                }
                
                // Top domains
                if (data.queries && data.queries.top_domains) {
                    let domainsHTML = '<div class="domain-list">';
                    
                    data.queries.top_domains.forEach(item => {
                        domainsHTML += `
                            <div class="domain-item">
                                <span>${item.domain}</span>
                                <span>${item.count.toLocaleString()}</span>
                            </div>
                        `;
                    });
                    
                    domainsHTML += '</div>';
                    topDomains.innerHTML = domainsHTML;
                } else {
                    topDomains.innerHTML = '<p>No domain statistics available</p>';
                }
                
                // Top blocked domains
                if (data.queries && data.queries.top_blocked) {
                    let blockedHTML = '<div class="domain-list">';
                    
                    data.queries.top_blocked.forEach(item => {
                        blockedHTML += `
                            <div class="domain-item">
                                <span>${item.domain}</span>
                                <span>${item.count.toLocaleString()}</span>
                            </div>
                        `;
                    });
                    
                    blockedHTML += '</div>';
                    topBlocked.innerHTML = blockedHTML;
                } else {
                    topBlocked.innerHTML = '<p>No blocked domain statistics available</p>';
                }
            } else {
                queryStats.innerHTML = '<p>Error fetching statistics</p>';
                blocklistStats.innerHTML = '<p>Error fetching statistics</p>';
                systemInfo.innerHTML = '<p>Error fetching statistics</p>';
                topDomains.innerHTML = '<p>Error fetching statistics</p>';
                topBlocked.innerHTML = '<p>Error fetching statistics</p>';
            }
        }
        
        // Function to update categories
        async function updateCategories() {
            const categoriesElement = document.getElementById('categories');
            const data = await fetchAPI('/api/config');
            
            if (data && data.categories) {
                let categoriesHTML = '';
                
                for (const [category, info] of Object.entries(data.categories)) {
                    categoriesHTML += `
                        <div class="category-item">
                            <div>
                                <strong>${category.charAt(0).toUpperCase() + category.slice(1)}</strong>
                                <p>${info.count.toLocaleString()} domains</p>
                            </div>
                            <label class="toggle-switch">
                                <input type="checkbox" class="category-toggle" data-category="${category}" ${info.enabled ? 'checked' : ''}>
                                <span class="slider"></span>
                            </label>
                        </div>
                    `;
                }
                
                categoriesElement.innerHTML = categoriesHTML;
                
                // Add event listeners to toggles
                document.querySelectorAll('.category-toggle').forEach(toggle => {
                    toggle.addEventListener('change', async function() {
                        const category = this.dataset.category;
                        const enabled = this.checked;
                        
                        const action = enabled ? 'enable_category' : 'disable_category';
                        const result = await postAPI('/api/control', {
                            action: action,
                            category: category
                        });
                        
                        if (result && result.success) {
                            alert(`Category '${category}' ${enabled ? 'enabled' : 'disabled'} successfully`);
                        } else {
                            alert(`Error ${enabled ? 'enabling' : 'disabling'} category '${category}'`);
                            this.checked = !enabled; // Revert toggle if failed
                        }
                    });
                });
            } else {
                categoriesElement.innerHTML = '<p>Error fetching categories</p>';
            }
        }
        
        // Add event listeners to buttons
        document.getElementById('start-button').addEventListener('click', async function() {
            const result = await postAPI('/api/control', { action: 'start' });
            if (result && result.success) {
                alert('DNS server started successfully');
                updateServerStatus();
            } else {
                alert('Error starting DNS server');
            }
        });
        
        document.getElementById('stop-button').addEventListener('click', async function() {
            const result = await postAPI('/api/control', { action: 'stop' });
            if (result && result.success) {
                alert('DNS server stopped successfully');
                updateServerStatus();
            } else {
                alert('Error stopping DNS server');
            }
        });
        
        document.getElementById('restart-button').addEventListener('click', async function() {
            const result = await postAPI('/api/control', { action: 'restart' });
            if (result && result.success) {
                alert('DNS server restarted successfully');
                updateServerStatus();
            } else {
                alert('Error restarting DNS server');
            }
        });
        
        document.getElementById('update-button').addEventListener('click', async function() {
            this.disabled = true;
            this.textContent = 'Updating...';
            
            const result = await postAPI('/api/control', { action: 'update' });
            
            this.disabled = false;
            this.textContent = 'Update Blocklists';
            
            if (result && result.success) {
                alert('Blocklists updated successfully');
                updateStatistics();
                updateCategories();
            } else {
                alert('Error updating blocklists');
            }
        });
        
        // Initialize page
        async function initPage() {
            await updateServerStatus();
            await updateStatistics();
            await updateCategories();
            
            // Refresh data periodically
            setInterval(updateServerStatus, 30000); // Every 30 seconds
            setInterval(updateStatistics, 60000);   // Every minute
        }
        
        // Start when page loads
        window.addEventListener('load', initPage);
    </script>
</body>
</html>
EOF

# Create systemd service for BIND logging
print_status "Creating systemd services..."
cat > /etc/systemd/system/filterdns-logger.service << EOF
[Unit]
Description=FilterDNS Query Logger
After=bind9.service

[Service]
Type=simple
User=root
ExecStart=/opt/filterdns/bin/log-dns-queries.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create timer for DNS query logging
cat > /etc/systemd/system/filterdns-logger.timer << EOF
[Unit]
Description=Run FilterDNS Query Logger every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

# Create systemd service for API server
cat > /etc/systemd/system/filterdns-api.service << EOF
[Unit]
Description=FilterDNS API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/filterdns
ExecStart=/opt/filterdns/bin/api-server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create cron job for updating blocklists
print_status "Setting up cron jobs..."
cat > /etc/cron.d/filterdns << EOF
# FilterDNS cron jobs

# Update blocklists daily at 3:00 AM
0 3 * * * root /opt/filterdns/bin/update-blocklists.sh > /dev/null 2>&1

# Rotate logs weekly
0 0 * * 0 root find /opt/filterdns/logs -type f -name "*.log" -mtime +7 -delete
EOF

# Configure log rotation
cat > /etc/logrotate.d/filterdns << EOF
/opt/filterdns/logs/*.log {
  weekly
  rotate 4
  compress
  missingok
  notifempty
  create 0644 root root
}
EOF

# Configure BIND logging
print_status "Configuring BIND logging..."
cat > /etc/bind/named.conf.logging << EOF
logging {
  channel query_log {
      file "/var/log/named/query.log" versions 3 size 5m;
      severity info;
      print-time yes;
      print-severity yes;
      print-category yes;
  };
  
  channel default_log {
      file "/var/log/named/default.log" versions 3 size 5m;
      severity info;
      print-time yes;
      print-severity yes;
      print-category yes;
  };
  
  category queries { query_log; };
  category default { default_log; };
  category config { default_log; };
  category security { default_log; };
};
EOF

# Update main BIND configuration to include logging
if ! grep -q "named.conf.logging" /etc/bind/named.conf; then
    sed -i '/include "\/etc\/bind\/named.conf.default-zones";/a include "\/etc\/bind\/named.conf.logging";' /etc/bind/named.conf
fi

# Create log directory
mkdir -p /var/log/named
chown bind:bind /var/log/named
chmod 755 /var/log/named

# Create custom blocklist and whitelist files
print_status "Creating initial blocklist files..."
mkdir -p /opt/filterdns/data/blocklists
touch /opt/filterdns/data/blocklists/custom.txt
cat > /opt/filterdns/data/blocklists/whitelist.txt << EOF
# Whitelist - Domains that should never be blocked
# Add one domain per line

# Examples:
# safedomain.com
# trusted-site.org
EOF

# Create directories for each category
for category in adult malware ads tracking; do
  mkdir -p "/opt/filterdns/data/blocklists/$category"
done

# Enable and start services
print_status "Enabling and starting services..."
systemctl daemon-reload
systemctl enable bind9
systemctl restart bind9
systemctl enable filterdns-api.service
systemctl start filterdns-api.service
systemctl enable filterdns-logger.timer
systemctl start filterdns-logger.timer

# Run initial blocklist update
print_status "Running initial blocklist update..."
/opt/filterdns/bin/update-blocklists.sh

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

# Print final information
clear
echo -e "${BOLD}${GREEN}=================================================${NC}"
echo -e "${BOLD}${GREEN}       FilterDNS Server Setup Complete!          ${NC}"
echo -e "${BOLD}${GREEN}=================================================${NC}"
echo
echo "Your DNS filtering server is now set up and running!"
echo
echo "DNS Server Information:"
echo "  - BIND DNS server is installed and configured"
echo "  - Content filtering is enabled with Response Policy Zones (RPZ)"
echo "  - Blocklists are automatically updated daily at 3:00 AM"
echo
echo "Web Interface:"
echo "  - Access the web interface at http://${SERVER_IP}:8080"
echo "  - Use the web interface to manage filtering categories and view statistics"
echo
echo "DNS Server Management:"
echo "  - Control the DNS server with: /opt/filterdns/bin/dns-control.sh"
echo "  - View server status: /opt/filterdns/bin/dns-control.sh status"
echo "  - Update blocklists: /opt/filterdns/bin/dns-control.sh update"
echo
echo "To use this DNS server on your network:"
echo "  1. Configure your devices to use ${SERVER_IP} as the DNS server"
echo "  2. Or configure your router to use this server as the DNS server for your network"
echo
echo "For more information, check the logs at:"
echo "  - /var/log/syslog (for BIND logs)"
echo "  - /opt/filterdns/logs/blocklist-update.log (for blocklist updates)"
echo
echo -e "${YELLOW}Note: This is a basic setup. For production use, consider adding SSL/TLS encryption and authentication to the web interface.${NC}"
echo

exit 0
