package sn

import "strings"

func parseString(input string) string {
	return strings.Replace(strings.TrimSpace(input), "\n", ",", -1)
}
