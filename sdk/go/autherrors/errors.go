package autherrors

import "errors"

var (
	ErrMaxUsesExceeded = errors.New("maximum capability uses exceeded")
	ErrLeaseRejected   = errors.New("capability consumption rejected")
	ErrUnavailable     = errors.New("capability consumption unavailable")
)
