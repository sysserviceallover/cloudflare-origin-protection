# Cloudflare AWS Security Group Sync

A production-safe Python script that automatically synchronizes AWS Security Group rules with Cloudflare's IP ranges. This ensures your infrastructure only allows traffic from legitimate Cloudflare edge servers.

## Overview

This script fetches the latest Cloudflare IP ranges and updates your AWS Security Group rules on a per-port basis, maintaining strict synchronization between Cloudflare's published IPs and your security group configuration. 

This script helps protect your origin server from hackers, scrapers, and bots that try to bypass Cloudflare by connecting directly to your server's IP. Normally, even if you use Cloudflare, attackers could still hit your server directly if they discover its AWS public IP. By keeping your AWS Security Group restricted only to Cloudflare's official IP ranges, the script ensures that all traffic must pass through Cloudflare's filtering, DDoS protection, and bot management layers. This way, only clean, validated requests reach your server, while all other direct connections are blocked automatically.

## Features

- ✅ **Per-port synchronization** - Manages rules independently for each configured port
- ✅ **Incremental updates** - Only adds/removes rules that have changed
- ✅ **Batch processing** - Handles large IP lists efficiently with configurable batch sizes
- ✅ **Dry-run mode** - Preview changes before applying them
- ✅ **Comprehensive logging** - Detailed logs with timestamps for audit trails
- ✅ **Error handling** - Robust retry logic and graceful error recovery
- ✅ **IPv4 and IPv6 support** - Handles both IP versions automatically

## Prerequisites

### Operating System Compatibility

This script is compatible with:
- **Ubuntu** 18.04+ (recommended)
- **Amazon Linux** 2/2023
- **CentOS/RHEL** 7+
- **Debian** 10+
- **macOS** 10.15+ (for local testing)

### Required Software

- **Python** 3.6 or higher
- **pip** package manager
- **AWS CLI** (recommended for initial setup)

## Installation

### 1. System Dependencies

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv curl -y
```

#### Amazon Linux:
```bash
sudo yum update -y
sudo yum install python3 python3-pip curl -y
```

#### CentOS/RHEL:
```bash
sudo yum update -y
sudo yum install python3 python3-pip curl -y
# For CentOS 8+:
# sudo dnf install python3 python3-pip curl -y
```

#### macOS:
```bash
# Using Homebrew
brew install python3
```

### 2. Python Dependencies

Create a virtual environment (recommended):
```bash
python3 -m venv cf-sg-sync
source cf-sg-sync/bin/activate
```

Install required packages:
```bash
pip install boto3 requests python-dotenv ipaddress
```

Or install globally:
```bash
sudo pip3 install boto3 requests python-dotenv ipaddress
```

### 3. Download the Script

```bash
# Download to your preferred location
cd /home/ubuntu  # or your preferred directory
git clone https://github.com/sysserviceallover/cloudflare-origin-protection.git
cd cloudflare-origin-protection
chmod +x update_cf_sg.py
```

## AWS Setup

### 1. Create IAM User

Create a dedicated IAM user for the script with minimal required permissions:

1. **Navigate to IAM Console**:
   - Go to AWS Console → IAM → Users → Add User

2. **Create User**:
   - User name: `cloudflare-sg-sync`
   - Access type: Programmatic access

3. **Attach Custom Policy**:
   Create a custom policy with these permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ec2:DescribeSecurityGroups",
           "ec2:AuthorizeSecurityGroupIngress",
           "ec2:RevokeSecurityGroupIngress"
         ],
         "Resource": "*",
         "Condition": {
           "StringEquals": {
             "ec2:Region": "your-region"
           }
         }
       }
     ]
   }
   ```

#### EC2 Instance Role (For EC2 deployment)
1. Create an IAM role with the same policy as above
2. Attach the role to your EC2 instance
3. No additional configuration needed

### 3. Find Your Security Group ID

#### Using AWS Console:
1. Go to EC2 Console → Security Groups
2. Find your target security group
3. Copy the Security Group ID (format: sg-xxxxxxxxx)

## Configuration

### 1. Create Environment File

Create a `.env` file in the same directory as the script:
```bash
nano .env
```

Add the following configuration:
```bash
# Security Group ID to update (REQUIRED)
SECURITY_GROUP_ID=sg-xxxxxxxxx

# AWS region where the Security Group exists (REQUIRED)
AWS_REGION=us-east-1

# Ports to manage (optional, defaults to 80,443)
PORTS=80,443

# Log file path (optional, defaults to /var/log/cf_sg_sync.log)
LOG_FILE=/home/ubuntu/cf_sg_update.log
```

### 2. Set Proper Permissions

```bash
# Make the script executable
chmod +x update_cf_sg.py

# Secure the environment file
chmod 600 .env

# Ensure log directory exists and is writable
sudo mkdir -p $(dirname "$LOG_FILE")
sudo chown $USER:$USER $(dirname "$LOG_FILE")
```

## Usage

### Basic Usage

```bash
# Run with default settings
sudo python3 update_cf_sg.py

# Preview changes without applying (recommended first run)
sudo python3 update_cf_sg.py --dry-run

# Run with detailed debug output
sudo python3 update_cf_sg.py --debug

# Combine flags
sudo python3 update_cf_sg.py --dry-run --debug
```

### Command Line Arguments

- `--dry-run`: Show planned changes without applying them
- `--debug`: Print detailed information including IP lists per port

### Example Output

```
[2025-09-01 15:30:22 UTC] Starting Cloudflare SG sync (per-port strict mode)...
[2025-09-01 15:30:23 UTC] Port 80: CF IPv4=14 SG IPv4=12 | CF IPv6=2 SG IPv6=2
[2025-09-01 15:30:23 UTC]   Plan for port 80: +v4=2 -v4=0 +v6=0 -v6=0
[2025-09-01 15:30:23 UTC] Port 443: CF IPv4=14 SG IPv4=14 | CF IPv6=2 SG IPv6=2
[2025-09-01 15:30:23 UTC]   Plan for port 443: +v4=0 -v4=0 +v6=0 -v6=0
[2025-09-01 15:30:24 UTC] Authorized IPv4 2 on port 80
[2025-09-01 15:30:24 UTC] Cloudflare SG sync completed successfully.
```

## Automation

### Set up Cron Job

To automatically sync Cloudflare IPs (recommended: daily):

```bash
# Edit crontab
sudo crontab -e

# Add daily sync at 3:00 AM
0 3 * * * /usr/bin/python3 /home/ubuntu/update_cf_sg.py >> /home/ubuntu/cf_sg_cron.log 2>&1

# Add weekly sync with debug output (Sundays at 2:00 AM)
0 2 * * 0 /usr/bin/python3 /home/ubuntu/update_cf_sg.py --debug >> /home/ubuntu/cf_sg_weekly.log 2>&1
```

## Security Considerations

### Best Practices

1. **Least Privilege**: The IAM user should only have permissions for the specific security group
2. **Credential Security**: Never store AWS credentials in the script or commit them to version control
3. **Log Monitoring**: Regularly review logs for unauthorized changes or errors
4. **Backup Rules**: Document your original security group rules before first run
5. **Testing**: Always test with `--dry-run` in production environments

### Network Security

- This script modifies **ingress rules only**
- It only affects the ports you specify in the PORTS configuration
- Existing rules for other ports/protocols remain unchanged
- The script maintains existing non-Cloudflare rules on configured ports

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| SECURITY_GROUP_ID | Yes | None | AWS Security Group ID (sg-xxxxxxxxx) |
| AWS_REGION | Yes | None | AWS region where SG exists |
| PORTS | No | 80,443 | Comma-separated list of ports to manage |
| LOG_FILE | No | /var/log/cf_sg_sync.log | Path to log file |

### Script Constants

You can modify these in the script if needed:
- `BATCH_SIZE = 40` - Number of IPs to process per API call
- `HTTP_TIMEOUT = 15` - Cloudflare API timeout in seconds
- `HTTP_RETRIES = 4` - Number of retry attempts for failed requests
- `HTTP_BACKOFF = 1.5` - Exponential backoff multiplier

## Monitoring and Maintenance

### Log Analysis

Monitor your logs regularly:

```bash
# View recent activity
tail -f /home/ubuntu/cf_sg_update.log

# Search for errors
grep -i error /home/ubuntu/cf_sg_update.log

# View daily summaries
grep "Starting Cloudflare SG sync" /home/ubuntu/cf_sg_update.log
```

## Performance Notes

### Expected Runtime

- **Small deployments** (< 20 IPs): 5-15 seconds
- **Large deployments** (> 100 IPs): 30-60 seconds
- **First run** (full sync): May take 2-3 minutes

### API Rate Limits

- **Cloudflare API**: No authentication required, generous limits
- **AWS EC2 API**: Subject to your account's API limits
- **Batch processing**: Reduces API calls and improves reliability

## Migration from Other Solutions

### From Manual Management

1. Document your current security group rules
2. Run the script with `--dry-run` to see planned changes
3. Backup your security group configuration
4. Run the script to sync with Cloudflare IPs

### From Other Scripts

1. Disable your existing automation
2. Clean up any conflicting rules manually
3. Configure this script according to your requirements
4. Test thoroughly with `--dry-run`

## FAQ

### Q: How often should I run this script?
**A**: Daily is recommended. Cloudflare occasionally updates their IP ranges, and daily sync ensures you're always current without overwhelming the APIs.

### Q: Will this affect my existing security group rules?
**A**: The script only manages rules for the ports you specify in the PORTS configuration. Rules for other ports and protocols remain untouched.

### Q: What happens if Cloudflare's API is down?
**A**: The script will retry with exponential backoff. If all retries fail, it logs the error and exits without making changes to preserve your existing rules.

### Q: Can I run this on multiple security groups?
**A**: Currently, the script handles one security group per configuration. To manage multiple groups, create separate .env files and run the script multiple times.

### Q: Is IPv6 supported?
**A**: Yes, the script automatically handles both IPv4 and IPv6 Cloudflare ranges.

## Support

### Getting Help

1. **Check logs first**: Most issues are logged with clear error messages
2. **Test connectivity**: Ensure you can reach both Cloudflare and AWS APIs
3. **Verify permissions**: Confirm your IAM user has the required permissions
4. **Run dry-run**: Use `--dry-run --debug` to diagnose issues without making changes

### Common Error Codes

- `InvalidGroup.NotFound`: Security group doesn't exist or wrong region
- `UnauthorizedOperation`: Insufficient IAM permissions
- `InvalidPermission.Duplicate`: Rule already exists (usually harmless)
- `InvalidPermission.NotFound`: Rule doesn't exist when trying to delete (usually harmless)

## License

This script is provided as-is for managing Cloudflare-AWS integrations. Please ensure compliance with your organization's security policies and AWS best practices.

## Changelog

### v1.0
- Initial release with per-port synchronization
- IPv4 and IPv6 support
- Comprehensive error handling and logging
- Dry-run and debug modes
