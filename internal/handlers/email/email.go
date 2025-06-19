package email

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"math/big"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	env "github.com/imrany/vilesql/config"
)

// SMTPConfig holds the SMTP server configuration
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// EmailData represents an email message
type EmailData struct {
	To      []string
	Subject string
	Body    string
	IsHTML  bool
}

// OTPData represents OTP information
type OTPData struct {
	Code      string
	ExpiresAt time.Time
	Purpose   string // e.g., "login", "password_reset", "verification"
}

// Global SMTP configuration
var config SMTPConfig

// Initialize SMTP configuration from environment variables
var port, _ = strconv.Atoi(env.GetValue("SMTP_PORT"))
func init() {
	config = SMTPConfig{
		Host:     env.GetValue("SMTP_HOST"),
		Port:     port,
		Username: env.GetValue("SMTP_USERNAME"),
		Password: env.GetValue("SMTP_PASSWORD"),
		From:     env.GetValue("SMTP_FROM"),
	}
}

// SetConfig allows manual configuration of SMTP settings
func SetConfig(cfg SMTPConfig) {
	config = cfg
}

// SendEmail sends a generic email
func SendEmail(emailData EmailData) error {
	if config.Username == "" || config.Password == "" {
		return fmt.Errorf("SMTP credentials not configured: %v", config)
	}

	// Create authentication
	auth := smtp.PlainAuth("", config.Username, config.Password, config.Host)

	// Build message
	message := buildMessage(emailData)

	// SMTP server address
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	// Send email with TLS
	return sendWithTLS(addr, auth, config.From, emailData.To, []byte(message))
}

// SendOTP generates and sends an OTP via email
func SendOTP(email, purpose string) (string, error) {
	// Generate OTP
	otp := GenerateOTP()
	
	// Create email content
	subject := getOTPSubject(purpose)
	body := getOTPBody(otp, purpose)
	
	emailData := EmailData{
		To:      []string{email},
		Subject: subject,
		Body:    body,
		IsHTML:  true,
	}
	
	// Send email
	err := SendEmail(emailData)
	if err != nil {
		return "", fmt.Errorf("failed to send OTP email: %w", err)
	}
	
	log.Printf("OTP sent successfully to %s for purpose: %s", email, purpose)
	return otp, nil
}

// GenerateOTP generates a secure random OTP
func GenerateOTP() string {
	// Generate 6-digit OTP
	otp := ""
	for i := 0; i < 6; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(10))
		otp += num.String()
	}
	return otp
}

// GenerateOTPWithLength generates OTP with custom length
func GenerateOTPWithLength(length int) string {
	if length <= 0 {
		length = 6
	}
	
	otp := ""
	for i := 0; i < length; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(10))
		otp += num.String()
	}
	return otp
}

// GenerateAlphanumericOTP generates alphanumeric OTP
func GenerateAlphanumericOTP(length int) string {
	if length <= 0 {
		length = 6
	}
	
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	otp := ""
	for i := 0; i < length; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		otp += string(chars[num.Int64()])
	}
	return otp
}

// SendOTPWithCustomTemplate sends OTP with custom email template
func SendOTPWithCustomTemplate(email, purpose, subject, htmlTemplate, textTemplate string) (string, error) {
	otp := GenerateOTP()
	
	// Replace placeholders in templates
	htmlBody := strings.ReplaceAll(htmlTemplate, "{{OTP}}", otp)
	htmlBody = strings.ReplaceAll(htmlBody, "{{PURPOSE}}", purpose)
	
	textBody := strings.ReplaceAll(textTemplate, "{{OTP}}", otp)
	textBody = strings.ReplaceAll(textBody, "{{PURPOSE}}", purpose)
	
	// Create multipart message
	body := buildMultipartMessage(htmlBody, textBody)
	
	emailData := EmailData{
		To:      []string{email},
		Subject: subject,
		Body:    body,
		IsHTML:  true,
	}
	
	err := SendEmail(emailData)
	if err != nil {
		return "", fmt.Errorf("failed to send OTP email: %w", err)
	}
	
	return otp, nil
}

// Helper functions

func buildMessage(emailData EmailData) string {
	var message strings.Builder
	
	// Headers
	message.WriteString(fmt.Sprintf("From: %s\r\n", config.From))
	message.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(emailData.To, ", ")))
	message.WriteString(fmt.Sprintf("Subject: %s\r\n", emailData.Subject))
	
	if emailData.IsHTML {
		message.WriteString("MIME-Version: 1.0\r\n")
		message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	} else {
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	}
	
	message.WriteString("\r\n")
	message.WriteString(emailData.Body)
	
	return message.String()
}

func buildMultipartMessage(htmlBody, textBody string) string {
	boundary := fmt.Sprintf("boundary_%d", time.Now().Unix())
	
	var message strings.Builder
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%s\r\n", boundary))
	message.WriteString("\r\n")
	
	// Text part
	message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	message.WriteString("\r\n")
	message.WriteString(textBody)
	message.WriteString("\r\n")
	
	// HTML part
	message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	message.WriteString("\r\n")
	message.WriteString(htmlBody)
	message.WriteString("\r\n")
	
	message.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	
	return message.String()
}

func sendWithTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	// Connect to server
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Close()
	
	// Start TLS
	tlsConfig := &tls.Config{
		ServerName: config.Host,
	}
	
	if err = client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}
	
	// Authenticate
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	
	// Set sender
	if err = client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	
	// Set recipients
	for _, recipient := range to {
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}
	
	// Send message
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	
	_, err = writer.Write(msg)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}
	
	return client.Quit()
}

// Creates OTP Email Subject
func getOTPSubject(purpose string) string {
	switch purpose {
	case "login":
		return "Your Login Verification Code"
	case "password_reset":
		return "Password Reset Verification Code"
	case "verification":
		return "Account Verification Code"
	case "registration":
		return "Registration Verification Code"
	default:
		return "Your Verification Code"
	}
}

func getOTPBody(otp, purpose string) string {
	switch purpose {
	case "login":
		return fmt.Sprintf(`
			<html>
			<body>
				<h2>Login Verification</h2>
				<p>Your login verification code is: <strong>%s</strong></p>
				<p>This code will expire in 10 minutes.</p>
				<p>If you didn't request this code, please ignore this email.</p>
			</body>
			</html>
		`, otp)
	case "password_reset":
		return fmt.Sprintf(`
			<html>
			<body>
				<h2>Password Reset</h2>
				<p>Your password reset verification code is: <strong>%s</strong></p>
				<p>This code will expire in 15 minutes.</p>
				<p>If you didn't request this code, please ignore this email.</p>
			</body>
			</html>
		`, otp)
	default:
		return fmt.Sprintf(`
			<html>
			<body>
				<h2>Verification Code</h2>
				<p>Your verification code is: <strong>%s</strong></p>
				<p>This code will expire in 10 minutes.</p>
			</body>
			</html>
		`, otp)
	}
}