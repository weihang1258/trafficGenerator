-- Migration 001: Initial schema
-- Create tasks table
CREATE TABLE IF NOT EXISTS tasks (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description VARCHAR(1024),
    protocol VARCHAR(32) NOT NULL,
    spec TEXT,
    interface VARCHAR(64),
    output_mode VARCHAR(32),
    pcap_file VARCHAR(512),
    status VARCHAR(32) NOT NULL DEFAULT 'created',
    progress REAL DEFAULT 0,
    error VARCHAR(1024),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- Create index on protocol
CREATE INDEX IF NOT EXISTS idx_tasks_protocol ON tasks(protocol);
-- Create index on status
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);

-- Create strategies table
CREATE TABLE IF NOT EXISTS strategies (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    protocol VARCHAR(32) NOT NULL,
    config TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on protocol
CREATE INDEX IF NOT EXISTS idx_strategies_protocol ON strategies(protocol);

-- Create history table
CREATE TABLE IF NOT EXISTS history (
    id VARCHAR(64) PRIMARY KEY,
    task_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    protocol VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    packets_sent BIGINT DEFAULT 0,
    bytes_sent BIGINT DEFAULT 0,
    duration INTEGER DEFAULT 0,
    error VARCHAR(1024),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- Create index on task_id
CREATE INDEX IF NOT EXISTS idx_history_task_id ON history(task_id);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    email VARCHAR(128) UNIQUE,
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP
);

-- Create index on username
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Create port_allocations table
CREATE TABLE IF NOT EXISTS port_allocations (
    id SERIAL PRIMARY KEY,
    interface VARCHAR(64) NOT NULL,
    port INTEGER NOT NULL,
    task_id VARCHAR(64),
    allocated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- Create index on interface and port
CREATE INDEX IF NOT EXISTS idx_port_allocations_iface_port ON port_allocations(interface, port);
-- Create index on task_id
CREATE INDEX IF NOT EXISTS idx_port_allocations_task_id ON port_allocations(task_id);

-- Insert default admin user (password: admin)
INSERT INTO users (username, password_hash, email, role)
VALUES ('admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.eG1H2IpmZyIaYqFOiu', 'admin@localhost', 'admin')
ON CONFLICT (username) DO NOTHING;
