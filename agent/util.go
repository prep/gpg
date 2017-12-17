package agent

import "strings"

var (
	decoder = strings.NewReplacer("%25", "%", "%0D", "\r", "%0A", "\n")
	encoder = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
)

func decode(source string) string {
	return decoder.Replace(source)
}

func encode(source string) string {
	return encoder.Replace(source)
}
