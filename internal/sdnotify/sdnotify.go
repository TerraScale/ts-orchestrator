// Package sdnotify implements the systemd service notification protocol in
// pure Go: READY=1 once a service is usable, STOPPING=1 on shutdown and
// WATCHDOG=1 keepalives while a health check passes. Outside systemd, or for
// a unit without Type=notify, NOTIFY_SOCKET is unset and every call is a
// no-op.
package sdnotify

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Notifier sends datagrams to the service manager's notification socket.
type Notifier struct {
	socket string
	// watchdog is half of WATCHDOG_USEC when it applies to this process.
	watchdog time.Duration
}

var processNotifier = captureEnvironment()

func Process() *Notifier { return processNotifier }

func captureEnvironment() *Notifier {
	notifier := New(os.Getenv("NOTIFY_SOCKET"), os.Getenv("WATCHDOG_USEC"), os.Getenv("WATCHDOG_PID"), os.Getpid())
	for _, name := range []string{"NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"} {
		_ = os.Unsetenv(name)
	}
	return notifier
}

// New builds a notifier from explicit environment values.
func New(socket, watchdogUSec, watchdogPID string, pid int) *Notifier {
	notifier := &Notifier{}
	if strings.HasPrefix(socket, "/") || strings.HasPrefix(socket, "@") {
		notifier.socket = socket
	}
	if usec, err := strconv.ParseUint(watchdogUSec, 10, 63); err == nil && usec > 0 {
		owner, pidErr := strconv.Atoi(watchdogPID)
		if watchdogPID == "" || pidErr == nil && owner == pid {
			notifier.watchdog = time.Duration(usec) * time.Microsecond / 2
		}
	}
	return notifier
}

// Enabled reports whether a notification socket is configured.
func (n *Notifier) Enabled() bool { return n != nil && n.socket != "" }

// Notify sends one state message such as "READY=1".
func (n *Notifier) Notify(state string) error {
	if !n.Enabled() {
		return nil
	}
	if state == "" || strings.ContainsRune(state, 0) {
		return errors.New("invalid service notification")
	}
	address := &net.UnixAddr{Name: n.socket, Net: "unixgram"}
	if strings.HasPrefix(n.socket, "@") {
		address.Name = "\x00" + n.socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte(state))
	return err
}

// Ready reports that the service finished starting.
func (n *Notifier) Ready(status string) error {
	message := "READY=1"
	if status != "" {
		message += "\nSTATUS=" + strings.ReplaceAll(status, "\n", " ")
	}
	return n.Notify(message)
}

// Stopping reports that the service began an orderly shutdown.
func (n *Notifier) Stopping() error { return n.Notify("STOPPING=1") }

// ExtendStart asks systemd for extension more time to finish starting
// (EXTEND_TIMEOUT_USEC), counted from now.
func (n *Notifier) ExtendStart(extension time.Duration) error {
	return n.Notify("EXTEND_TIMEOUT_USEC=" + strconv.FormatInt(extension.Microseconds(), 10))
}
