### System Overview
This web application allows users to:

1. Register and login to their accounts
2. Create, view, and manage multiple SQLite databases
3. Execute SQL queries against their databases
4. Create and modify database tables and data
5. Share databases with others via unique links (read-only access)
6. Delete databases when no longer needed

### Key Components

1. #### User Management System

- Registration and authentication
- Session management for protected routes
- Secure password handling using bcrypt


2. #### Database Management

- Creating new SQLite databases
- Listing user's databases
- Getting database schema (tables and columns)
- Sharing and unsharing databases
- Deleting databases


3. #### Query Execution

- Executing SQL queries on user databases
- Read-only access for shared databases
- Security measures to prevent unauthorized access


4. #### Table Management

- Creating new tables with custom schemas
- Inserting data into tables
- Deleting tables



5. #### Security Features

- Password hashing using bcrypt
- Session-based authentication
- Database ownership validation
- Read-only mode for shared databases
- Prevention of write operations on shared databases
- Size limits on databases

### Setup and Configuration
The application uses several configurable constants:

- HTTP port (default: 5050)
- Storage path for user databases
- Session and cookie keys (should be replaced with secure values)
- Database size limits
- Token expiration for shared links

### API Endpoints
#### Authentication

- POST `/api/register` - Create a new user account
- POST `/api/login` - Authenticate a user
- POST `/api/logout` - End a user session

#### Database Management (authenticated)

- GET `/api/databases` - List user's databases
- POST `/api/databases` - Create a new database
- GET `/api/databases/{id}` - Get database details
- DELETE `/api/databases/{id}` - Delete a database
- POST `/api/databases/{id}/share` - Generate share link
- DELETE `/api/databases/{id}/share` - Disable sharing

#### Data Operations (authenticated)

- POST `/api/databases/{id}/query` - Execute SQL query
- POST `/api/databases/{id}/tables` - Create a new table
- DELETE `/api/databases/{id}/tables/{table}` - Delete a table
- POST `/api/databases/{id}/data` - Insert data into a table

#### Shared Access (public)

- GET `/api/shared/{token}` - Access a shared database
- POST `/api/shared/{token}/query` - Query a shared database (read-only)

Configure the constants in the code (especially security keys)
Build the application: go build -o vilesql
Run the server: ./vilesql
