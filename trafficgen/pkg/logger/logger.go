// Package logger provides structured logging using Zap.
package logger

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Global logger instance.
	Log *zap.Logger
	// Sugar logger for convenient usage.
	Sugar *zap.SugaredLogger
)

// Config for logger initialization.
type Config struct {
	Level  string // debug, info, warn, error
	Format string // json, console
	Output string // stdout, stderr, file
}

// Init initializes the global logger.
func Init(cfg Config) error {
	// Parse log level
	level, err := zapcore.ParseLevel(strings.ToLower(cfg.Level))
	if err != nil {
		level = zapcore.InfoLevel
	}

	// Configure encoder
	var encoder zapcore.Encoder
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	if strings.ToLower(cfg.Format) == "console" {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// Configure output
	var writeSyncer zapcore.WriteSyncer
	switch strings.ToLower(cfg.Output) {
	case "stderr":
		writeSyncer = zapcore.AddSync(os.Stderr)
	case "stdout", "":
		writeSyncer = zapcore.AddSync(os.Stdout)
	default:
		// File output - simplified, in production use lumberjack for rotation
		file, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		writeSyncer = zapcore.AddSync(file)
	}

	// Create core
	core := zapcore.NewCore(encoder, writeSyncer, level)

	// Create logger
	Log = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	Sugar = Log.Sugar()

	// Replace global zap logger so zap.L() works
	zap.ReplaceGlobals(Log)

	return nil
}

// Sync flushes any buffered log entries.
func Sync() error {
	if Log != nil {
		return Log.Sync()
	}
	return nil
}

// Debug logs a debug message.
func Debug(msg string, fields ...zap.Field) {
	Log.Debug(msg, fields...)
}

// Info logs an info message.
func Info(msg string, fields ...zap.Field) {
	Log.Info(msg, fields...)
}

// Warn logs a warning message.
func Warn(msg string, fields ...zap.Field) {
	Log.Warn(msg, fields...)
}

// Error logs an error message.
func Error(msg string, fields ...zap.Field) {
	Log.Error(msg, fields...)
}

// Fatal logs a fatal message and exits.
func Fatal(msg string, fields ...zap.Field) {
	Log.Fatal(msg, fields...)
}

// With creates a child logger with additional fields.
func With(fields ...zap.Field) *zap.Logger {
	return Log.With(fields...)
}

// Named creates a named logger.
func Named(name string) *zap.Logger {
	return Log.Named(name)
}
