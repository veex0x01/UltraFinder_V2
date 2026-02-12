package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TelegramNotifier sends alerts via Telegram Bot API
type TelegramNotifier struct {
	BotToken string
	ChatID   string
	client   *http.Client
}

// NewTelegramNotifier creates a new Telegram notifier
func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
	return &TelegramNotifier{
		BotToken: botToken,
		ChatID:   chatID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (t *TelegramNotifier) Name() string { return "telegram" }

func (t *TelegramNotifier) Send(alert Alert) error {
	text := fmt.Sprintf("*%s*\n\n%s\n\n_%s_",
		escapeMarkdown(alert.Title),
		escapeMarkdown(alert.Message),
		alert.Timestamp.Format("2006-01-02 15:04:05 UTC"))

	payload := map[string]interface{}{
		"chat_id":    t.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}

	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.BotToken)

	resp, err := t.client.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Telegram API returned status %d", resp.StatusCode)
	}
	return nil
}

func escapeMarkdown(s string) string {
	replacer := []string{
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"`", "\\`",
	}
	for i := 0; i < len(replacer); i += 2 {
		s = replaceAll(s, replacer[i], replacer[i+1])
	}
	return s
}

func replaceAll(s, old, new string) string {
	var result []byte
	for i := 0; i < len(s); i++ {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result = append(result, []byte(new)...)
			i += len(old) - 1
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}

// SlackNotifier sends alerts via Slack webhooks
type SlackNotifier struct {
	WebhookURL string
	Channel    string
	client     *http.Client
}

// NewSlackNotifier creates a new Slack notifier
func NewSlackNotifier(webhookURL, channel string) *SlackNotifier {
	return &SlackNotifier{
		WebhookURL: webhookURL,
		Channel:    channel,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackNotifier) Name() string { return "slack" }

func (s *SlackNotifier) Send(alert Alert) error {
	// Slack severity color
	color := "#36a64f" // green
	switch alert.Severity {
	case "CRITICAL":
		color = "#ff0000"
	case "HIGH":
		color = "#ff4444"
	case "MEDIUM":
		color = "#ffaa00"
	case "LOW":
		color = "#0088ff"
	}

	payload := map[string]interface{}{
		"channel": s.Channel,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  alert.Title,
				"text":   alert.Message,
				"footer": "UltraFinder v2.0",
				"ts":     alert.Timestamp.Unix(),
			},
		},
	}

	data, _ := json.Marshal(payload)
	resp, err := s.client.Post(s.WebhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// DiscordNotifier sends alerts via Discord webhooks
type DiscordNotifier struct {
	WebhookURL string
	client     *http.Client
}

// NewDiscordNotifier creates a new Discord notifier
func NewDiscordNotifier(webhookURL string) *DiscordNotifier {
	return &DiscordNotifier{
		WebhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *DiscordNotifier) Name() string { return "discord" }

func (d *DiscordNotifier) Send(alert Alert) error {
	color := 0x36a64f // green
	switch alert.Severity {
	case "CRITICAL":
		color = 0xff0000
	case "HIGH":
		color = 0xff4444
	case "MEDIUM":
		color = 0xffaa00
	case "LOW":
		color = 0x0088ff
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       alert.Title,
				"description": alert.Message,
				"color":       color,
				"footer":      map[string]string{"text": "UltraFinder v2.0"},
				"timestamp":   alert.Timestamp.Format(time.RFC3339),
			},
		},
	}

	data, _ := json.Marshal(payload)
	resp, err := d.client.Post(d.WebhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("Discord webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// WebhookNotifier sends alerts to any generic webhook
type WebhookNotifier struct {
	URL    string
	client *http.Client
}

// NewWebhookNotifier creates a new generic webhook notifier
func NewWebhookNotifier(url string) *WebhookNotifier {
	return &WebhookNotifier{
		URL:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *WebhookNotifier) Name() string { return "webhook" }

func (w *WebhookNotifier) Send(alert Alert) error {
	payload := map[string]interface{}{
		"title":     alert.Title,
		"message":   alert.Message,
		"severity":  alert.Severity,
		"target":    alert.Target,
		"timestamp": alert.Timestamp.Format(time.RFC3339),
		"results":   alert.Results,
	}

	data, _ := json.Marshal(payload)
	resp, err := w.client.Post(w.URL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
