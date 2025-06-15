### **🚀 VileSQL: SQLite Database Hosting & Management**  
VileSQL offers **server-mode SQLite database hosting** with **controlled access**, allowing developers to efficiently manage their SQLite databases remotely.

<!-- --- -->

## **📌 Features**
✔ **Cloud-hosted SQLite databases** – Access SQLite as a server-based solution.  
✔ **Secure authentication with API tokens** – Prevent unauthorized access.  
✔ **Simple integration with Golang** – Lightweight and developer-friendly.  
✔ **Run SQL queries via API** – No need for local SQLite instances.  

<!-- --- -->

## **🛠 Getting Started**
### **1️⃣ Install & Import VileSQL Package**
Ensure you have VileSQL installed in your Go project:
```sh
go get github.com/imrany/vilesql/driver
```

Import it into your code:
```go
package main

import (
    "fmt"
    vilesql "github.com/imrany/vilesql/driver"
)
```

<!-- --- -->

### **2️⃣ Initialize the Connection**
Set up credentials and establish a connection:
```go
func main() {
    db := vilesql.Driver{
        Credentials: vilesql.Credentials{
            Host:  "https://vilesql.villebiz.com", // VileSQL host
            Token: "your-api-token",
        },
    }

    // Connect to the database
    if err := db.Connect(); err != nil {
        fmt.Println("Connection failed:", err)
        return
    }

    fmt.Println("✅ Connected to VileSQL successfully!")
}
```

<!-- --- -->

### **3️⃣ Running SQL Queries**
Once connected, **execute SQL queries via API**:
```go
query := "SELECT * FROM users"
result, err := db.Run(query)

if err != nil {
    fmt.Println("❌ Query execution failed:", err)
} else {
    fmt.Println("✅ Query result:", result)
}
```

<!-- --- -->

## **🎯 Why VileSQL?**
🔹 **Server-mode SQLite access** – No local database required  
🔹 **Simple API authentication** – Secure access via tokens  
🔹 **Seamless integration with Golang** – Minimal setup required  
