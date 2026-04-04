# Configuration Templates

This directory contains configuration templates for different deployment scenarios.

## Available Templates

| Template | Description |
|----------|-------------|
| `config.dev.yaml` | Development environment (debug mode, no Redis) |
| `config.standalone.yaml` | Standalone deployment (SQLite, no Redis) |
| `config.docker.yaml` | Docker Compose deployment (with Redis, PostgreSQL ready) |

## Usage

### Quick Start

```bash
# Copy the appropriate template to config.yaml
cp configs/config.standalone.yaml configs/config.yaml

# Edit with your settings
vim configs/config.yaml
```

### Environment Variables

Templates support environment variable substitution using `${VAR_NAME}` syntax:

```yaml
auth:
  jwt_secret: "${JWT_SECRET}"
  admin:
    username: "${ADMIN_USERNAME}"
    password: "${ADMIN_PASSWORD}"
    email: "${ADMIN_EMAIL}"
```

Set environment variables before starting:

```bash
export JWT_SECRET="your-secure-secret"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="your-secure-password"
export ADMIN_EMAIL="admin@example.com"
```

### Deployment Examples

#### Development

```bash
cp configs/config.dev.yaml configs/config.yaml
./bin/trafficgen -config configs/config.yaml
```

#### Standalone Production

```bash
cp configs/config.standalone.yaml configs/config.yaml
# Edit config.yaml with production values
./bin/trafficgen -config configs/config.yaml
```

#### Docker Compose

```bash
cp configs/config.docker.yaml configs/config.yaml
# Set environment variables
export JWT_SECRET="production-secret"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="secure-password"
export ADMIN_EMAIL="admin@example.com"
docker-compose up -d
```

## Configuration Reference

### Server

| Field | Description | Default |
|-------|-------------|---------|
| `server.host` | Listen address | `0.0.0.0` |
| `server.port` | Listen port | `8080` |
| `server.mode` | Gin mode (debug/release/test) | `release` |

### Database

| Field | Description | Default |
|-------|-------------|---------|
| `database.type` | Database type (sqlite/postgres) | `sqlite` |
| `database.sqlite.path` | SQLite database file path | `./data/trafficgen.db` |
| `database.postgres.*` | PostgreSQL connection settings | - |

### Redis

| Field | Description | Default |
|-------|-------------|---------|
| `redis.enabled` | Enable Redis caching | `false` |
| `redis.addr` | Redis address | `localhost:6379` |

### Auth

| Field | Description | Default |
|-------|-------------|---------|
| `auth.jwt_secret` | JWT signing secret | Required |
| `auth.jwt_issuer` | JWT issuer | `trafficgen` |
| `auth.jwt_expires_in` | Token expiry (hours) | `24` |
| `auth.admin.username` | Default admin username | `admin` |
| `auth.admin.password` | Default admin password | Required |
| `auth.admin.email` | Default admin email | Required |

## Important Notes

1. **`config.yaml` is ignored by git** - Your actual configuration with secrets won't be committed
2. **Templates are tracked by git** - Update templates when adding new config options
3. **Admin account** - Configured via config file, cannot be created/modified via API
