package logging

import (
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog with application-specific configuration
type Logger struct {
	*zerolog.Logger
}

// Config holds logging configuration
type Config struct {
	Level      string // debug, info, warn, error
	Format     string // json, console
	TimeFormat string // timestamp format
}

// NewLogger creates a new logger with the given configuration
func NewLogger(cfg Config) *Logger {
	// Set global time format for all zerolog instances
	zerolog.TimeFieldFormat = time.RFC3339

	// Parse log level
	level := parseLogLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)

	var output io.Writer = os.Stdout

	// Configure output format
	if cfg.Format == "console" {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: cfg.TimeFormat,
			NoColor:    os.Getenv("NO_COLOR") != "",
		}
	}

	logger := zerolog.New(output).With().Timestamp().Logger()

	return &Logger{
		Logger: &logger,
	}
}

// parseLogLevel converts string level to zerolog.Level
func parseLogLevel(level string) zerolog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zerolog.DebugLevel
	case "info", "":
		return zerolog.InfoLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	case "disabled":
		return zerolog.Disabled
	default:
		return zerolog.InfoLevel
	}
}

// Global logger instance
var globalLogger *Logger

// InitGlobalLogger initializes the global logger
func InitGlobalLogger(cfg Config) {
	globalLogger = NewLogger(cfg)
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		// Fallback to default logger
		globalLogger = NewLogger(Config{
			Level:  "info",
			Format: "json",
		})
	}
	return globalLogger
}

// Convenience functions that use the global logger
func Debug() *zerolog.Event {
	return GetLogger().Debug()
}

func Info() *zerolog.Event {
	return GetLogger().Info()
}

func Warn() *zerolog.Event {
	return GetLogger().Warn()
}

func Error() *zerolog.Event {
	return GetLogger().Error()
}

func Fatal() *zerolog.Event {
	return GetLogger().Fatal()
}

// WithRequest creates a logger with request context
func WithRequest(method, path, userAgent string) *zerolog.Logger {
	logger := GetLogger().With().
		Str("method", method).
		Str("path", path).
		Str("user_agent", userAgent).
		Logger()
	return &logger
}

// WithError creates a logger with error context
func WithError(err error) *zerolog.Event {
	return GetLogger().Error().Err(err)
}

// WithFields creates a logger with custom fields
func WithFields(fields map[string]interface{}) *zerolog.Logger {
	context := GetLogger().With()
	for k, v := range fields {
		context = context.Interface(k, v)
	}
	logger := context.Logger()
	return &logger
}

// LoadConfigFromEnv loads logging configuration from environment variables
func LoadConfigFromEnv() Config {
	return Config{
		Level:      getEnv("LOG_LEVEL", "info"),
		Format:     getEnv("LOG_FORMAT", "json"),
		TimeFormat: getEnv("LOG_TIME_FORMAT", "15:04:05"),
	}
}

// getEnv gets environment variable with fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetBoolEnv gets boolean environment variable
func GetBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}