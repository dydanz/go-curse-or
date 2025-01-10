# Go-Cursor User Management API

A RESTful API service built with Go (Gin framework) that handles user management with PostgreSQL for data persistence and Redis for caching.

## Features

- RESTful API endpoints for user management (CRUD operations)
- PostgreSQL database with UUID as primary key
- Password hashing using bcrypt
- Redis caching
- Docker support for local development
- Environment-based configuration

## Prerequisites

Before you begin, ensure you have installed:
- Go 1.16 or later
- Docker and Docker Compose
- Git

## Getting Started

### 1. Clone the Repository

### 2. Set Up Environment Variables

Create a `.env` file in the project root:
```env
# PostgreSQL Settings
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres123
DB_NAME=go_cursor

# Redis Settings
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=redis123
```

### 3. Start Dependencies (PostgreSQL and Redis)

```bash
docker-compose up -d
```

### 4. Install Go Dependencies

```bash
go mod tidy
```

### 5. Initialize Database

Connect to PostgreSQL and create the users table:

```bash
docker exec -it $(docker ps -qf "name=postgres") psql -U postgres -d go_cursor
```

Then run the following SQL:

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
```

### 6. Run the Application

```bash
go run cmd/api/main.go
```

The API will be available at `http://localhost:8080`

## API Endpoints

### Create User
```bash
curl -X POST http://localhost:8080/api/users \
-H "Content-Type: application/json" \
-d '{
    "email": "john@example.com",
    "password": "password123",
    "name": "John Doe",
    "phone": "1234567890"
}'
```

### Get All Users
```bash
curl http://localhost:8080/api/users
```

### Get User by ID
```bash
curl http://localhost:8080/api/users/{user_id}
```

### Update User
```bash
curl -X PUT http://localhost:8080/api/users/{user_id} \
-H "Content-Type: application/json" \
-d '{
    "name": "John Updated",
    "phone": "0987654321"
}'
```

### Delete User
```bash
curl -X DELETE http://localhost:8080/api/users/{user_id}
```

## Project Structure

```
go-cursor/
├── cmd/
│   └── api/
│       └── main.go
├── internal/
│   ├── config/
│   │   └── config.go
│   ├── domain/
│   │   └── user.go
│   ├── repository/
│   │   ├── postgres/
│   │   │   └── user_repository.go
│   │   └── redis/
│   │       └── cache_repository.go
│   ├── handler/
│   │   └── user_handler.go
│   └── service/
│       └── user_service.go
├── pkg/
│   └── database/
│       ├── postgres.go
│       └── redis.go
├── docker-compose.yml
├── .env
└── go.mod
```

## Development

### Running Tests

```bash
go test ./... -v
```

### Common Issues

1. Database Connection Issues
   - Check if PostgreSQL container is running: `docker ps`
   - Verify .env credentials match docker-compose.yml
   - Wait a few seconds after starting containers

2. Redis Connection Issues
   - Check if Redis container is running: `docker ps`
   - Verify Redis password in .env matches docker-compose.yml

3. "Module Not Found" Errors
   - Run `go mod tidy` to fix dependencies
   - Check if module name in imports matches go.mod

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| DB_HOST | PostgreSQL host | localhost |
| DB_PORT | PostgreSQL port | 5432 |
| DB_USER | PostgreSQL username | postgres |
| DB_PASSWORD | PostgreSQL password | postgres123 |
| DB_NAME | PostgreSQL database name | go_cursor |
| REDIS_HOST | Redis host | localhost |
| REDIS_PORT | Redis port | 6379 |
| REDIS_PASSWORD | Redis password | redis123 |

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details

## Acknowledgments

- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [Go-Redis](https://github.com/go-redis/redis)
- [Lib/pq](https://github.com/lib/pq)