# FilterDNS - Complete All-in-One Setup Script with Nginx

FilterDNS is a comprehensive setup script designed to create a fully functional DNS filtering server with a web interface and Nginx. This script automates the installation and configuration of several components, including BIND9, Nginx, Fail2Ban, and various DNS filtering mechanisms.

## Features

- Installs and configures BIND9 as the DNS server
- Sets up Nginx as a reverse proxy for the web interface
- Implements DNS filtering using Response Policy Zones (RPZ)
- Automatically updates blocklists daily
- Provides a web interface for managing the DNS server and viewing statistics
- Secures the server with Fail2Ban and UFW firewall

## Prerequisites

- A system running a Debian-based Linux distribution (e.g., Ubuntu)
- Root privileges

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/likhonsheikh54/FiltersDNS.git
    cd FiltersDNS
    ```

2. Make the setup script executable:

    ```bash
    chmod +x dns.sh
    ```

3. Run the setup script as root:

    ```bash
    sudo ./dns.sh
    ```

## Usage

### DNS Server Management

Use the `dns-control.sh` script to manage the DNS server. The script provides the following commands:

- **status**: Show DNS server status
- **start**: Start DNS server
- **stop**: Stop DNS server
- **restart**: Restart DNS server
- **reload**: Reload DNS configuration
- **update**: Update blocklists
- **enable [cat]**: Enable a category (adult, malware, ads, tracking)
- **disable [cat]**: Disable a category (adult, malware, ads, tracking)
- **stats**: Show DNS server statistics
- **help**: Show help message

Example:

```bash
sudo /opt/filterdns/bin/dns-control.sh status
```

### Web Interface

Access the web interface to manage filtering categories and view statistics:

- **URL**: `http://<your-server-ip>`

A test page is available at `http://<your-server-ip>/test.html`.

### Blocklist Management

The `update-blocklists.sh` script is used to download and process blocklists for DNS filtering. It supports multiple categories such as adult, malware, ads, and tracking.

### Log Management

- **DNS Query Logs**: `/var/log/named/query.log`
- **Web Interface Access Logs**: `/var/log/nginx/filterdns.access.log`
- **Blocklist Update Logs**: `/opt/filterdns/logs/blocklist-update.log`
- **System Logs**: `/var/log/syslog`

### Security Features

- **Fail2Ban**: Protects against brute force attacks
- **UFW Firewall**: Configures firewall rules to allow only necessary ports

### Optimizations

The system is optimized for DNS server performance by adjusting various kernel parameters.

## Additional Information

The script configures Nginx as a reverse proxy and sets up Fail2Ban and UFW firewall for added security. It also creates systemd services and timers for DNS query logging and blocklist updates.

For detailed documentation and troubleshooting, please refer to the official [documentation](https://docs.github.com/en/copilot).

---

*Note: For production use, consider setting up SSL/TLS with Let's Encrypt:*

```bash
sudo certbot --nginx -d yourdomain.com
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [BIND9](https://www.isc.org/bind/)
- [Nginx](https://www.nginx.com/)
- [Fail2Ban](https://www.fail2ban.org/)
- [UFW](https://help.ubuntu.com/community/UFW)
- [Let's Encrypt](https://letsencrypt.org/)

---

*FilterDNS - DNS Filtering Server &copy; 2025 | [Documentation](https://docs.github.com/en/copilot)*

For any issues or contributions, feel free to open an issue or a pull request on the [GitHub repository](https://github.com/likhonsheikh54/FiltersDNS).
