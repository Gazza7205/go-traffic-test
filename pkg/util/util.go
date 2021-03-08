package util

import (
	"log"
	"strings"
)

// ErrorCheck - generic error handler
func ErrorCheck(err error) {
	if err != nil {
		log.Println(err.Error())
		return
	}
}

//Contains - check if []string contains value
func Contains(arr []string, str string) bool {
	for _, a := range arr {
		if strings.Contains(a, str) {
			return true
		}
	}
	return false
}
