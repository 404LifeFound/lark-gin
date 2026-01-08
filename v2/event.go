package larkgin

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/go-lark/lark/v2"
)

// GetEvent should call GetEvent if you're using EventV2
func (opt LarkMiddleware) GetEvent(c *gin.Context) (*lark.Event, bool) {
	if message, ok := c.Get(opt.messageKey); ok {
		event, ok := message.(lark.Event)
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
				opt.logger.Log(c, lark.LogLevelDebug, "decrypt encrypt string success")
			}
			inputBody = []byte(decrypte_string)
		}

		var event lark.Event
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
