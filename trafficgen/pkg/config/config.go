// Package config provides configuration loading and management.
package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Engine   EngineConfig   `mapstructure:"engine"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
}

// ServerConfig for HTTP server.
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"` // debug, release, test
}

// DatabaseConfig for database connection.
type DatabaseConfig struct {
	Type    string        `mapstructure:"type"`
	Postgres PostgresConfig `mapstructure:"postgres"`
	SQLite   SQLiteConfig   `mapstructure:"sqlite"`
	Pool     PoolConfig     `mapstructure:"pool"`
}

// PostgresConfig for PostgreSQL connection.
type PostgresConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

// SQLiteConfig for SQLite connection.
type SQLiteConfig struct {
	Path string `mapstructure:"path"`
}

// PoolConfig for connection pool.
type PoolConfig struct {
	MaxOpen     int           `mapstructure:"max_open"`
	MaxIdle     int           `mapstructure:"max_idle"`
	ConnLifetime time.Duration `mapstructure:"conn_lifetime"`
}

// RedisConfig for Redis connection.
type RedisConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	PoolSize int    `mapstructure:"pool_size"`
}

// EngineConfig for traffic engine.
type EngineConfig struct {
	ConfigWorkers int `mapstructure:"config_workers"`
	PacketWorkers int `mapstructure:"packet_workers"`
	OutputWorkers int `mapstructure:"output_workers"`
	BufferSize    int `mapstructure:"buffer_size"`
	QueueSize     int `mapstructure:"queue_size"`
}

// LoggingConfig for logging.
type LoggingConfig struct {
	Level  string    `mapstructure:"level"`
	Format string    `mapstructure:"format"`
	Output string    `mapstructure:"output"`
	File   FileConfig `mapstructure:"file"`
}

// FileConfig for log file.
type FileConfig struct {
	Path       string `mapstructure:"path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

// JWTConfig for JWT authentication.
type JWTConfig struct {
	Secret string        `mapstructure:"secret"`
	Issuer string        `mapstructure:"issuer"`
	Expiry time.Duration `mapstructure:"expiry"`
}

// RateLimitConfig for API rate limiting.
type RateLimitConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	RequestsPerSecond int  `mapstructure:"requests_per_second"`
	Burst             int  `mapstructure:"burst"`
}

// MetricsConfig for Prometheus metrics.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// Load loads configuration from file.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Read config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("./configs")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/trafficgen")
	}

	// Environment variables
	v.SetEnvPrefix("TG")
	v.AutomaticEnv()

	// Read config
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, use defaults
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.mode", "release")

	// Database defaults
	v.SetDefault("database.type", "sqlite")
	v.SetDefault("database.sqlite.path", "./data/trafficgen.db")
	v.SetDefault("database.pool.max_open", 100)
	v.SetDefault("database.pool.max_idle", 10)
	v.SetDefault("database.pool.conn_lifetime", "1h")

	// Redis defaults
	v.SetDefault("redis.enabled", true)
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.pool_size", 100)

	// Engine defaults
	v.SetDefault("engine.config_workers", 4)
	v.SetDefault("engine.packet_workers", 8)
	v.SetDefault("engine.output_workers", 4)
	v.SetDefault("engine.buffer_size", 4096)
	v.SetDefault("engine.queue_size", 1024)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")

	// JWT defaults
	v.SetDefault("jwt.secret", "change-me-in-production")
	v.SetDefault("jwt.issuer", "trafficgen")
	v.SetDefault("jwt.expiry", "24h")

	// Rate limit defaults
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.requests_per_second", 100)
	v.SetDefault("rate_limit.burst", 200)

	// Metrics defaults
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.path", "/metrics")
}

// GetDSN returns the database connection string.
func (c *DatabaseConfig) GetDSN() string {
	switch c.Type {
	case "postgres":
		return fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			c.Postgres.Host,
			c.Postgres.Port,
			c.Postgres.User,
			c.Postgres.Password,
			c.Postgres.DBName,
			c.Postgres.SSLMode,
		)
	case "sqlite":
		return c.SQLite.Path
	default:
		return ""
	}
}
