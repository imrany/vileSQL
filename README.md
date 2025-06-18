### **🚀 VileSQL: SQLite Database Hosting & Management**  
VileSQL offers **server-mode SQLite database hosting, powerful, cloud-hosted SQLite DBMS** with **secure database hosting, controlled access, and an intuitive control panel** for managing your databases effortlessly.

## **📌 Features**
✔ **Cloud-hosted SQLite databases** – No need to install or configure SQLite manually.  
✔ **Secure authentication with API tokens** – Ensure **safe and private** data access.  
✔ **Intuitive Control Panel** – Manage users, queries, and settings with a **user-friendly dashboard**.  
✔ **Automated Backups** – Never lose your data, even in critical operations.  
✔ **Query Execution & Monitoring** – Track real-time database activity in the **control panel**.  
✔ **Performance Optimization** – Indexing and caching mechanisms for **faster queries**.  


## **🔗 Getting Started**
### **1️⃣ Create Your Account**
Sign up at **[https://bit.ly/vilesql](https://bit.ly/vilesql)**

### **2️⃣ Access Your Control Panel**
Once registered, log in to the **VileSQL Control Panel** to:
- Manage databases  
- Monitor query performance  
- Set up automated backups  

### **3️⃣ Connect Your Application**
Use **API requests** to interact with the database programmatically:
```bash
   curl -X POST -H "Content-Type: application/json" -d '{"sql":"SELECT * FROM mytable"}'  https://example.com/api/shared/<your-token>/query
```

Or, integrate with **Golang**:

[GoLang integration documentation](./Docs/golang.md)

## **🛠️ Using VileSQL DBMS**
[▶️ Watch demo video](https://drive.google.com/file/d/1pbVJRTb5vDIw6WfXV8jwW--DIHQ7Du4y/view?usp=drive_web)


## **Build and Run with Docker**
```bash
docker build -t vilesql .
```

```bash
docker run -d -p 5000:5000 vilesql
```
### Using docker-compose
```bash
docker-compose up -d
```

## **Installation Guide**
Follow our installation guide [user guide](./Docs/userguide.md)


## **Usage: Example**
```bash
# Default: Silent background mode
vilesql

# Verbose foreground mode with full logging
vilesql --verbose

# Silent foreground mode (no daemon, but no logging)
vilesql --foreground

# Start on custom port
vilesql --port 8080

# Use custom data directory
vilesql --data-dir /path/to/data

# Show version
vilesql --version

# Check if updates are available
vilesql upgrade --check-only

# Include pre-release versions
vilesql upgrade --check-only --pre-release

# Standard upgrade with backup
vilesql upgrade

# Upgrade without creating backup
vilesql upgrade --no-backup-data

# Force upgrade even if same version
vilesql upgrade --force

# Include pre-release versions
vilesql upgrade --pre-release

# Uninstall with dry run
vilesql uninstall --dry-run

# Uninstall and remove data with backup
vilesql uninstall --remove-data

# Uninstall without backup
vilesql uninstall --remove-data --backup-data=false
```

## **🚀 Who Can Use VileSQL?**
✅ **Developers** – Build apps with **server-managed SQLite databases**  
✅ **Businesses** – Store, analyze, and manage critical data remotely  
✅ **Researchers & Educators** – Easily maintain structured datasets  
✅ **Organizations** – Enforce **RBAC-based access control**  

VileSQL gives you **the power of an enterprise-grade DBMS** while keeping **SQLite lightweight and accessible**.  


## Uninstalling VileSQL

### Package Manager Uninstallation

**Ubuntu/Debian:**
```bash
sudo apt remove vilesql
# To remove all data:
sudo apt purge vilesql
rm -rf ~/.vilesql
```
or 
```bash
sudo dpkg --remove vilesql
```

**CentOS/RHEL/Fedora**
```bash
sudo rpm -e vilesql
# Remove data manually:
rm -rf ~/.vilesql
sudo rm -rf /var/lib/vilesql
```

**macOS (Homebrew)**
```bash
brew uninstall vilesql
# Remove data:
rm -rf ~/.vilesql
rm -rf ~/Library/Application\ Support/vilesql
```

### Manual Uninstallation

1. Use built-in uninstall: 
```bash
vilesql uninstall --remove-data
```
2. Remove binary: 
```bash
sudo rm $(which vilesql)
```
3. Or download our uninstall script: 
```bash
curl -sSL https://raw.githubusercontent.com/imrany/vilesql/main/scripts/uninstall.sh | bash
```
