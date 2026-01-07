package larkgin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-lark/lark/v2"
)

// GetCardCallback from gin context
func (opt LarkMiddleware) GetCardCallback(c *gin.Context) (*CardActionTriggerEvent, bool) {
	if card, ok := c.Get(opt.cardKey); ok {
		msg, ok := card.(CardActionTriggerEvent)
		return &msg, ok
	}

	return nil, false
}

type CardActionTriggerEvent struct {
	Schema string `json:"schema"`
	Header Header `json:"header"`
	Event  Event  `json:"event"`
}

type Header struct {
	EventID    string `json:"event_id"`
	Token      string `json:"token"`
	CreateTime string `json:"create_time"`
	EventType  string `json:"event_type"`
	TenantKey  string `json:"tenant_key"`
	AppID      string `json:"app_id"`
}

type Event struct {
	Operator Operator `json:"operator"`
	Token    string   `json:"token"`
	Action   Action   `json:"action"`
	Host     string   `json:"host"`
	Context  Context  `json:"context"`
}

type Operator struct {
	TenantKey string `json:"tenant_key"`
	OpenID    string `json:"open_id"`
	UnionID   string `json:"union_id"`
}

type Action struct {
	Value ActionValue `json:"value"`
	Tag   string      `json:"tag"`
}

type EncryptEvent struct {
	Encrypt string `json:"encrypt"`
}

type ActionValue struct {
	Action      string `json:"action"`
	Description string `json:"description"`
	GrafanaURL  string `json:"grafana_url"`
	Metric      string `json:"metric"`
	Project     string `json:"project"`
	RunbookURL  string `json:"runbook_url"`
	Time        string `json:"time"`
	Title       string `json:"title"`
}

type Context struct {
	OpenMessageID string `json:"open_message_id"`
	OpenChatID    string `json:"open_chat_id"`
}

// LarkCardHandler card callback handler
func (opt LarkMiddleware) LarkCardHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer c.Next()
		body, err := fetchBody(c)
		if err != nil {
			return
		}
		var inputBody = body

		if opt.enableEncryption {
			// encryptkey verification
			nonce := c.Request.Header.Get("X-Lark-Request-Nonce")
			timestamp := c.Request.Header.Get("X-Lark-Request-Timestamp")
			signature := c.Request.Header.Get("X-Lark-Signature")
			sig := opt.cardSignature(nonce, timestamp, string(body), string(opt.encryptKey))
			if signature != sig {
				opt.logger.Log(c, lark.LogLevelError, "encryptkey verification failed")
				return
			}

			// decrypt encrypted event
			var encrypt_event EncryptEvent
			err = json.Unmarshal(inputBody, &encrypt_event)
			if err != nil {
				opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("Unmarshal JSON error: %v", err))
				return
			}

			decrypte_string, err := opt.decryptEncryptString(string(opt.encryptKey), encrypt_event.Encrypt)
			if err != nil {
				opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("decrypt encrypt string error: %v", err))
				return
			}

			var decrypt_event CardActionTriggerEvent
			err = json.Unmarshal([]byte(decrypte_string), &decrypt_event)
			if err != nil {
				opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("Unmarshal JSON error: %v", err))
				return
			}

			// verify verificationToken
			if opt.enableTokenVerification {
				if decrypt_event.Header.Token != opt.verificationToken {
					opt.logger.Log(c, lark.LogLevelWarn, "verification mismatched")
					return
				}
			}
			c.Set(opt.cardKey, decrypt_event)
		} else {
			var event CardActionTriggerEvent
			err = json.Unmarshal([]byte(inputBody), &event)
			if err != nil {
				opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("Unmarshal JSON error: %v", err))
				return
			}
			// verify verificationToken
			if opt.enableTokenVerification {
				if event.Header.Token != opt.verificationToken {
					opt.logger.Log(c, lark.LogLevelWarn, "verification mismatched")
					return
				}
			}
			c.Set(opt.cardKey, event)
		}
	}
}

func (opt LarkMiddleware) cardSignature(nonce, timestamp, bodystring, encryptKey string) string {
	var b strings.Builder
	b.WriteString(timestamp)
	b.WriteString(nonce)
	b.WriteString(encryptKey)
	b.WriteString(bodystring) //bodystring refers to the entire request body, do not calculate it after deserialization
	bs := []byte(b.String())
	h := sha256.New()
	h.Write(bs)
	bs = h.Sum(nil)
	sig := fmt.Sprintf("%x", bs)
	return sig
}

func (opt LarkMiddleware) decryptEncryptString(encryptKey string, cryptoText string) (string, error) {
	var key []byte
	{
		h := sha256.New()
		h.Write([]byte(encryptKey))
		key = h.Sum(nil)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(ciphertext, ciphertext)

	return string(ciphertext[:len(ciphertext)-int(ciphertext[len(ciphertext)-1])]), nil
}
