package larkgin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-lark/lark/v2"
)

// LarkChallengeHandler Lark challenge handler
func (opt LarkMiddleware) LarkChallengeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer c.Next()
		if opt.enableURLBinding && c.Request.URL.String() != opt.urlPrefix {
			// url not match just pass
			return
		}

		body, err := fetchBody(c)
		if err != nil {
			return
		}
		var inputBody = body
		if opt.enableEncryption {
			// decrypt encrypted event
			var encrypt_event EncryptEvent
			err = json.Unmarshal(inputBody, &encrypt_event)
			if err != nil {
				opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("Unmarshal Encrypted JSON error: %v", err))
				return
			} else {
				opt.logger.Log(c, lark.LogLevelDebug, "Unmarshal Encrypted JSON success")
			}
			decryptedData, err := opt.decryptEncryptString(string(opt.encryptKey), encrypt_event.Encrypt)
			if err != nil {
				opt.logger.Log(c, lark.LogLevelWarn, fmt.Sprintf("decrypt encrypt string error: %v", err))
				return
			} else {
				opt.logger.Log(c, lark.LogLevelDebug, "decrypt encrypt string success")
			}
			inputBody = []byte(decryptedData)
		}

		var challenge lark.EventChallenge
		err = json.Unmarshal(inputBody, &challenge)
		if err != nil {
			return
		}
		if challenge.Type == "url_verification" {
			opt.logger.Log(c, lark.LogLevelInfo, fmt.Sprintf("Handling challenge: %s", challenge.Challenge))
			c.AbortWithStatusJSON(http.StatusOK, gin.H{
				"challenge": challenge.Challenge,
			})
		}
	}
}
