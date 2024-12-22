package jwt

import (
	"crypto"
	"encoding/json"
	"errors"
)

type Token struct {
	Header  Header
	Payload any
}

type Header struct {
	Alg crypto.Hash `json:"alg"`
	Typ string      `json:"type"`
}

func (h Header) MarshalJSON() ([]byte, error) {
	if !h.Alg.Available() {
		return nil, errors.New("MarshalJSON: invalid signing algorith")
	}

	hashName := h.Alg.String()
	buf := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{
		Alg: hashName,
		Typ: "jwt",
	}

	return json.Marshal(buf)
}

// func (t Token) MarshalJSON() ([]byte, error) {

// }

// func (t Token) Sign() (string, error) {
// 	headerStr, err := t.Header.MarshalJSON()
// 	if err != nil {
// 		return "", err
// 	}

// 	payloadStr, err := json.Marshal(t.Payload)
// 	if err != nil {
// 		return "", err
// 	}
// 	body := make([]byte, len(headerStr))
// 	copy(body, headerStr)

// 	body = append(body, '.')
// 	body = append(body, payloadStr...)

// 	signature := make([]byte, 0)
// 	t.Header.Alg.New()
// }
