package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const availCharacters string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateInviteCode(length uint) (string, error) {
	if length%4 != 0 {
		return "", fmt.Errorf("length must be multiples of 4")
	}
	b := make([]byte, length/4*3)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}
