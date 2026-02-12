package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
)

// LogLevel represents logging severity
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// LogLevelNames maps levels to strings
var LogLevelNames = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Module    string `json:"module,omitempty"`
	Message   string `json:"message"`
}

// Logger provides structured leveled logging
type Logger struct {
	level    LogLevel
	file     *os.File
	mu       sync.Mutex
	jsonMode bool
	module   string
	callback func(LogLevel, string)
}

// NewLogger creates a new Logger instance
func NewLogger(logFile string, level LogLevel, jsonMode bool) (*Logger, error) {
	l := &Logger{
		level:    level,
		jsonMode: jsonMode,
	}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		l.file = f
	}

	return l, nil
}

// WithModule creates a child logger with a module tag
func (l *Logger) WithModule(module string) *Logger {
	return &Logger{
		level:    l.level,
		file:     l.file,
		jsonMode: l.jsonMode,
		module:   module,
	}
}

// Close closes the log file
func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

// Debug logs a debug-level message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info-level message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning-level message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error-level message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Success logs a success message (at INFO level with green color)
func (l *Logger) Success(format string, args ...interface{}) {
	if l.level > INFO {
		return
	}
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()

	color.New(color.FgGreen, color.Bold).Printf("[+] ")
	fmt.Println(msg)

	if l.file != nil {
		l.writeToFile(INFO, msg)
	}
}

func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()

	// Console output with colors
	var levelColor *color.Color
	switch level {
	case DEBUG:
		levelColor = color.New(color.FgWhite)
	case INFO:
		levelColor = color.New(color.FgBlue, color.Bold)
	case WARN:
		levelColor = color.New(color.FgYellow, color.Bold)
	case ERROR:
		levelColor = color.New(color.FgRed, color.Bold)
	}

	prefix := fmt.Sprintf("[%s]", LogLevelNames[level])
	if l.module != "" {
		prefix = fmt.Sprintf("[%s][%s]", LogLevelNames[level], l.module)
	}
	levelColor.Printf("%s ", prefix)
	fmt.Println(msg)

	// File output
	if l.file != nil {
		l.writeToFile(level, msg)
	}

	// Callback output (e.g. for Web UI)
	l.mu.Unlock() // Unlock before callback to avoid deadlocks in callback
	if l.callback != nil {
		l.callback(level, msg)
	}
}

// SetCallback sets a function to be called on every log entry
func (l *Logger) SetCallback(cb func(LogLevel, string)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.callback = cb
}

func (l *Logger) writeToFile(level LogLevel, msg string) {
	if l.jsonMode {
		entry := LogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     LogLevelNames[level],
			Module:    l.module,
			Message:   msg,
		}
		data, _ := json.Marshal(entry)
		fmt.Fprintln(l.file, string(data))
	} else {
		ts := time.Now().UTC().Format("2006-01-02 15:04:05")
		if l.module != "" {
			fmt.Fprintf(l.file, "%s [%s][%s] %s\n", ts, LogLevelNames[level], l.module, msg)
		} else {
			fmt.Fprintf(l.file, "%s [%s] %s\n", ts, LogLevelNames[level], msg)
		}
	}
}
