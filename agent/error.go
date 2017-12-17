package agent

import (
	"strconv"
	"strings"
)

// Error describes a gpg-agent error.
type Error struct {
	Code        int
	Description string
}

// NewError parses a gpg-agent error.
func NewError(line string) Error {
	part := strings.SplitN(line, " ", 3)
	if part[0] == "ERR" {
		part = part[1:]
	}

	if len(part) == 0 {
		return Error{Description: "unknown error"}
	}

	code, err := strconv.Atoi(part[0])
	if err != nil {
		return Error{Description: part[0]}
	} else if len(part) == 1 {
		return Error{Code: code, Description: "unknown error"}
	}

	return Error{Code: code, Description: part[1]}
}

// Error implements the error interface.
func (e Error) Error() string {
	return e.Description
}
