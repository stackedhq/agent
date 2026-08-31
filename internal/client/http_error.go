package client

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPError is a non-2xx response from the control plane.
type HTTPError struct {
	StatusCode int
	RetryAfter time.Duration
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// SendBackoff is how long a log shipper should pause after a send error.
// Only 429s back off; other errors drop the batch and continue.
func SendBackoff(err error) time.Duration {
	var httpErr *HTTPError
	if !asHTTPError(err, &httpErr) {
		return 0
	}
	if httpErr.StatusCode != http.StatusTooManyRequests {
		return 0
	}
	d := httpErr.RetryAfter
	if d <= 0 {
		d = 5 * time.Second
	}
	const maxBackoff = 30 * time.Second
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func asHTTPError(err error, target **HTTPError) bool {
	return errors.As(err, target)
}

func parseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	seconds, err := strconv.Atoi(header)
	if err != nil || seconds < 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}
