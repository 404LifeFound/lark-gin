package larkgin

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/go-lark/lark/v2"
)

type NormalEventCallback struct {
	Schema string       `json:"schema"`
	Header NormalHeader `json:"header"`
	Event  NormalEvent  `json:"event"`
}

/***************
 * Header
 ***************/
type NormalHeader struct {
	EventID    string `json:"event_id"`
	Token      string `json:"token"`
	CreateTime string `json:"create_time"`
	EventType  string `json:"event_type"`
	TenantKey  string `json:"tenant_key"`
	AppID      string `json:"app_id"`
}

/***************
 * Event
 ***************/
type NormalEvent struct {
	Message Message `json:"message"`
	Sender  Sender  `json:"sender"`
}

/***************
 * Message
 ***************/
type Message struct {
	ChatID      string    `json:"chat_id"`
	ChatType    string    `json:"chat_type"`
	Content     string    `json:"content"`
	CreateTime  string    `json:"create_time"`
	UpdateTime  string    `json:"update_time"`
	MessageID   string    `json:"message_id"`
	MessageType string    `json:"message_type"`
	Mentions    []Mention `json:"mentions"`
}

/***************
 * Mention
 ***************/
type Mention struct {
	ID        MentionID `json:"id"`
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	TenantKey string    `json:"tenant_key"`
}

type MentionID struct {
	OpenID  string `json:"open_id"`
	UnionID string `json:"union_id"`
	UserID  string `json:"user_id"`
}

/***************
 * Sender
 ***************/
type Sender struct {
	SenderID   SenderID `json:"sender_id"`
	SenderType string   `json:"sender_type"`
	TenantKey  string   `json:"tenant_key"`
}

type SenderID struct {
	OpenID  string `json:"open_id"`
	UnionID string `json:"union_id"`
	UserID  string `json:"user_id"`
}

func (opt LarkMiddleware) GetEvent(c *gin.Context) (*NormalEventCallback, bool) {
	if message, ok := c.Get(opt.messageKey); ok {
		event, ok := message.(NormalEventCallback)
		if event.Schema != "2.0" {
			return nil, false
		}
		return &event, ok
	}

	return nil, false
}

// LarkEventHandler handle lark event v2
func (opt LarkMiddleware) LarkEventHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer c.Next()
		body, err := fetchBody(c)
		if err != nil {
			return
		}
		var inputBody = body
		opt.logger.Log(c, lark.LogLevelDebug, fmt.Sprintf("inputbody: %s", string(inputBody)))
		if opt.enableEncryption {
			// verify signature
			nonce := c.Request.Header.Get("X-Lark-Request-Nonce")
			timestamp := c.Request.Header.Get("X-Lark-Request-Timestamp")
			signature := c.Request.Header.Get("X-Lark-Signature")
			sig := opt.cardSignature(nonce, timestamp, string(inputBody), string(opt.encryptKey))
			opt.logger.Log(c, lark.LogLevelDebug, fmt.Sprintf("nonce: %s,timestamp: %s,signature: %s,sig: %s", nonce, timestamp, signature, sig))
			if signature != sig {
				opt.logger.Log(c, lark.LogLevelError, "encryptkey verification failed")
				return
			}

			// decrypt encrypted event
			var encrypt_event EncryptEvent
			err = json.Unmarshal(inputBody, &encrypt_event)
			if err != nil {
				opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("Unmarshal Encrypted JSON error: %v", err))
				return
			} else {
				opt.logger.Log(c, lark.LogLevelDebug, "Unmarshal Encrypted JSON success")
			}

			decrypte_string, err := opt.decryptEncryptString(string(opt.encryptKey), encrypt_event.Encrypt)
			if err != nil {
				opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("decrypt encrypt string error: %v", err))
				return
			} else {
				opt.logger.Log(c, lark.LogLevelDebug, fmt.Sprintf("decrypt encrypt string success: %s", decrypte_string))
			}
			inputBody = []byte(decrypte_string)
		}

		var event NormalEventCallback
		err = json.Unmarshal(inputBody, &event)
		if err != nil {
			opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("Unmarshal JSON error: %v", err))
			return
		}
		if opt.enableTokenVerification && event.Header.Token != opt.verificationToken {
			opt.logger.Log(c, lark.LogLevelError, "Token verification failed")
			return
		}
		opt.logger.Log(c, lark.LogLevelInfo, fmt.Sprintf("Handling event: %s", event.Header.EventType))
		c.Set(opt.messageKey, event)
	}
}
