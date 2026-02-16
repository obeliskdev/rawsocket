package rawsocket

import (
	"github.com/obeliskdev/fastrand"
)

// validPort returns a valid port number.
// If the input port is less than or equal to 0, a random port number is generated.
// Otherwise, the input port is returned as is.
func validPort(port int) int {
	if port <= 0 {
		return fastrand.Int(1, 65535)
	}
	if port > 65535 {
		return 65535
	}
	return port
}
