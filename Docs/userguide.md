# VileSQL Upgrade Guide

This guide covers all the ways to upgrade your VileSQL installation to the latest version.

## Table of Contents

1. [Built-in Upgrade Command](#built-in-upgrade-command)
2. [Package Manager Upgrades](#package-manager-upgrades)
3. [Manual Upgrades](#manual-upgrades)
4. [Docker Upgrades](#docker-upgrades)
5. [Migration and Data Safety](#migration-and-data-safety)
6. [Troubleshooting](#troubleshooting)

## Built-in Upgrade Command

VileSQL includes a built-in upgrade system that automatically downloads and installs the latest version.

### Check for Updates

```bash
# Check if updates are available
vilesql upgrade --check-only

# Include pre-release versions
vilesql upgrade --check-only --pre-release
```

### Perform Upgrade

```bash
# Standard upgrade with backup
vilesql upgrade

# Upgrade without creating backup
vilesql upgrade --no-backup-data

# Force upgrade even if same version
vilesql upgrade --force

# Include pre-release versions
vilesql upgrade --pre-release
```

### Upgrade Process

1. **Version Check**: Compares current version with latest GitHub release
2. **Backup Creation**: Creates backup of data directory (if enabled)
3. **Download**: Downloads appropriate binary for your platform
4. **Installation**: Replaces current binary with new version
5. **Migration**: Runs any necessary data migrations
6. **Verification**: Confirms successful upgrade

## Package Manager Upgrades

### Homebrew (macOS)

```bash
# Update homebrew and upgrade vilesql
brew update
brew upgrade vilesql

# Or upgrade all packages
brew upgrade
```

### APT (Debian/Ubuntu)

```bash
# Download and install new .deb package
wget https://github.com/imrany/vilesql/releases/download/v1.2.0/vilesql_1.2.0_linux_amd64.deb
sudo dpkg -i vilesql_1.2.0_linux_amd64.deb

# The postupgrade script will automatically:
# - Run data migrations
# - Restart the service
# - Update systemd configuration
```

### RPM (RHEL/CentOS/Fedora)

```bash
# Download and install new .rpm package
wget https://github.com/imrany/vilesql/releases/download/v1.2.0/vilesql_1.2.0_amd64.rpm
sudo rpm -Uvh vilesql_1.2.0_amd64.rpm
```

### APK (Alpine Linux)

```bash
# Download and install new .apk package
wget https://github.com/imrany/vilesql/releases/download/v1.2.0/vilesql_1.2.0_amd64.apk
sudo apk add --allow-untrusted vilesql_1.2.0_amd64.apk
```

## Manual Upgrades

### Binary Replacement

1. **Download** the latest binary for your platform from [GitHub Releases](https://github.com/imrany/vilesql/releases)

2. **Backup** your current installation:
   ```bash
   # Backup binary
   cp $(which vilesql) vilesql.backup
   
   # Backup data
   vilesql uninstall --backup-data --dry-run  # Shows what would be backed up
   tar -czf vilesql-data-backup.tar.gz ~/.vilesql
   ```

3. **Replace** the binary:
   ```bash
   # Stop vilesql if running as a service
   sudo systemctl stop vilesql
   
   # Replace binary
   sudo cp vilesql /usr/local/bin/vilesql
   sudo chmod +x /usr/local/bin/vilesql
   ```

4. **Run migrations**:
   ```bash
   vilesql migrate
   ```

5. **Restart** service:
   ```bash
   sudo systemctl start vilesql
   ```

### From Source

```bash
# Clone the repository
git clone https://github.com/imrany/vilesql.git
cd vilesql

# Checkout the latest tag
git fetch --tags
git checkout $(git describe --tags --abbrev=0)

# Build
go build -o vilesql

# Install
sudo cp vilesql /usr/local/bin/vilesql
sudo chmod +x /usr/local/bin/vilesql

# Run migrations
vilesql migrate
```

## Docker Upgrades

### Docker Compose

```bash
# Pull latest image
docker-compose pull ghcr.io/imrany/vilesql:latest

# Recreate container with new image
docker-compose up -d vilesql

# Or restart entire stack
docker-compose down
docker-compose up -d
```

### Standalone Docker

```bash
# Pull latest image
docker pull ghcr.io/imrany/vilesql:latest

# Pull specific version
docker pull ghcr.io/imrany/vilesql:v0.5.3

# Stop current container
docker stop vilesql

# Remove old container
docker rm vilesql

# Start new container with same data volume
docker run -d -p 5000:5000 --name vilesql ghcr.io/imrany/vilesql:latest
```

### Kubernetes

```yaml
# Update your deployment with new image
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vilesql
spec:
  template:
    spec:
      containers:
      - name: vilesql
        image: ghcr.io/imrany/vilesql:lastest  # Update this
```

Apply the changes:
```bash
kubectl apply -f vilesql-deployment.yaml
kubectl rollout status deployment/vilesql
```

## Migration and Data Safety

### Data Migration System

VileSQL includes an automatic migration system that:

- **Detects** data directory version
- **Runs** necessary migrations for schema updates
- **Preserves** existing data
- **Creates** new directory structures as needed

### Manual Migration

```bash
# Run migrations manually
vilesql migrate

# Dry run to see what would be migrated
vilesql migrate --dry-run

# Force re-run all migrations
vilesql migrate --force
```

### Backup Strategy

Before upgrading, always create backups:

```bash
# Using built-in backup
vilesql upgrade --backup-data

# Manual backup
tar -czf vilesql-backup-$(date +%Y%m%d).tar.gz ~/.vilesql

# Database-specific backup
sqlite3 ~/.vilesql/databases/mydb.sqlite ".backup /path/to/backup.db"
```

### Data Directory Structure

```
~/.vilesql/
├── .version              # Version tracking
├── databases/           # SQLite database files
├── backups/             # Automatic backups
├── logs/                # Application logs
└── config/              # User configuration
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied During Upgrade

```bash
# Ensure you have write permissions
sudo chown $(whoami) $(which vilesql)

# Or run upgrade with sudo
sudo vilesql upgrade
```

#### 2. Migration Failures

```bash
# Check migration status
vilesql migrate --dry-run

# Reset to clean state (CAUTION: This removes data)
rm ~/.vilesql/.version
vilesql migrate
```

#### 3. Service Won't Start After Upgrade

```bash
# Check service status
systemctl status vilesql

# View logs
journalctl -u vilesql -f

# Restart service
sudo systemctl restart vilesql
```

#### 4. Binary Not Found After Upgrade

```bash
# Check if binary exists
which vilesql
ls -la /usr/local/bin/vilesql

# Re-download and install
wget https://github.com/imrany/vilesql/releases/download/v1.2.0/vilesql_1.2.0_linux_amd64.tar.gz
tar -xzf vilesql_1.2.0_linux_amd64.tar.gz
sudo cp vilesql /usr/local/bin/
```

### Recovery Procedures

#### Rollback to Previous Version

```bash
# If you have a backup binary
cp vilesql.backup $(which vilesql)

# Or download previous version
wget https://github.com/imrany/vilesql/releases/download/v1.1.0/vilesql_1.1.0_linux_amd64.tar.gz
# ... extract and install
```

#### Restore Data Backup

```bash
# Stop vilesql
sudo systemctl stop vilesql

# Restore from backup
tar -xzf vilesql-backup-20240101.tar.gz -C ~/

# Restart service
sudo systemctl start vilesql
```

### Getting Help

If you encounter issues during upgrade:

1. **Check Logs**: `journalctl -u vilesql -f`
2. **Review Documentation**: [GitHub Wiki](https://github.com/imrany/vilesql/wiki)
3. **Search Issues**: [GitHub Issues](https://github.com/imrany/vilesql/issues)
4. **Create Issue**: Include logs, OS details, and upgrade method used

## Upgrade Checklist

Before upgrading:

- [ ] **Backup** your data: `vilesql upgrade --backup-data` or manual backup
- [ ] **Check** current version: `vilesql --version`
- [ ] **Stop** services if running: `sudo systemctl stop vilesql`
- [ ] **Test** backup integrity: Verify you can restore if needed

During upgrade:

- [ ] **Monitor** progress and check for errors
- [ ] **Verify** binary replacement was successful
- [ ] **Run** migrations: `vilesql migrate`

After upgrade:

- [ ] **Verify** new version: `vilesql --version`
- [ ] **Test** functionality: Access web interface
- [ ] **Check** service status: `systemctl status vilesql`
- [ ] **Review** logs for any issues

---

## Version Compatibility

| VileSQL Version | Data Format | Migration Required |
|----------------|-------------|-------------------|
| 1.0.x          | v1.0        | No                |
| 1.1.x          | v1.1        | Yes (automatic)   |
| 1.2.x          | v1.2        | Yes (automatic)   |

Always review the [CHANGELOG](https://github.com/imrany/vilesql/blob/main/CHANGELOG.md) before upgrading to understand what changes are included in each version.