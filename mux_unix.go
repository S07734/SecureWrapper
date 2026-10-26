//go:build linux || darwin

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"securewrapper/connections"
)

// muxDefaultPersist is how long a master outlives its last client.
const muxDefaultPersist = 10 * time.Minute

// muxMasterSpec is handed to the master over its stdin pipe, so credentials
// never appear in argv or the environment.
type muxMasterSpec struct {
	Host     string        `json:"host"`
	Port     int           `json:"port"`
	Username string        `json:"username"`
	Password string        `json:"password"`
	KeyPath  string        `json:"key_path"`
	KeyPass  string        `json:"key_pass"`
	Socket   string        `json:"socket"`
	Token    string        `json:"token"`
	Persist  time.Duration `json:"persist"`
}

// muxSettings reads WRAPPER_MUX (0/off/no/false disables sharing) and
// WRAPPER_MUX_PERSIST (a Go duration, e.g. "30m").
func muxSettings() (time.Duration, bool) {
	switch strings.ToLower(os.Getenv("WRAPPER_MUX")) {
	case "0", "off", "no", "false":
		return 0, false
	}
	if v := os.Getenv("WRAPPER_MUX_PERSIST"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d, true
		}
	}
	return muxDefaultPersist, true
}

func muxDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secure-wrapper", "mux")
}

// muxSocketPath is short and fixed-length so it stays under the 104-byte
// sun_path limit on macOS.
func muxSocketPath(conn Connection) string {
	h := sha256.Sum256([]byte(conn.Name + "\x00" + conn.Username + "\x00" + conn.Host + "\x00" + strconv.Itoa(conn.Port)))
	return filepath.Join(muxDir(), hex.EncodeToString(h[:8])+".sock")
}

// muxToken is the local-hop password, derived from the stored credentials so
// only a caller that could decrypt this connection can use its master. A
// credential change yields a new token, which retires the old master.
func muxToken(conn Connection) string {
	mac := hmac.New(sha256.New, []byte("securewrapper-mux-v1"))
	for _, f := range []string{conn.Name, conn.Username, conn.Host, strconv.Itoa(conn.Port), conn.Password, conn.KeyPath, conn.KeyPass} {
		mac.Write([]byte(f))
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func muxCapable(conn Connection) bool {
	return conn.Type == ConnSSHPassword || conn.Type == ConnSSHKey || conn.Type == ConnFTP
}

// enableMux routes this connection's SSH dials through a shared master.
func enableMux(conn Connection) {
	persist, ok := muxSettings()
	if !ok || !muxCapable(conn) {
		return
	}
	sock, token := muxSocketPath(conn), muxToken(conn)
	connections.RegisterMux(conn.Username, conn.Host, conn.Port, &connections.MuxEndpoint{
		SocketPath: sock,
		Token:      token,
		Start:      func() error { return startMuxMaster(conn, sock, token, persist) },
	})
}

// startMuxMaster launches a detached master. A per-socket flock keeps
// concurrent callers from starting two masters for the same connection.
func startMuxMaster(conn Connection, sock, token string, persist time.Duration) error {
	if err := os.MkdirAll(muxDir(), 0700); err != nil {
		return err
	}
	if err := os.Chmod(muxDir(), 0700); err != nil {
		return err
	}

	lock, err := os.OpenFile(sock+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}

	// Another caller may have started one while we waited for the lock.
	if c, err := connections.DialMux(sock, token); err == nil {
		c.Close()
		return nil
	}
	// Stale socket from a dead master, or a live one holding old credentials.
	os.Remove(sock)
	os.Remove(sock + ".pub")

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readyR.Close()

	cmd := exec.Command(exe, "--mux-master")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.ExtraFiles = []*os.File{readyW} // fd 3 in the child
	cmd.Env = muxChildEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		readyW.Close()
		return err
	}
	if err := cmd.Start(); err != nil {
		readyW.Close()
		return err
	}
	readyW.Close()

	spec := muxMasterSpec{
		Host: conn.Host, Port: conn.Port, Username: conn.Username,
		Password: conn.Password, KeyPath: conn.KeyPath, KeyPass: conn.KeyPass,
		Socket: sock, Token: token, Persist: persist,
	}
	json.NewEncoder(stdin).Encode(spec)
	stdin.Close()
	cmd.Process.Release()

	readyR.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, _ := bufio.NewReader(readyR).ReadString('\n')
	line = strings.TrimSpace(line)
	switch {
	case line == "ok":
		return nil
	case strings.HasPrefix(line, "upstream: "):
		return &connections.MuxUpstreamError{Msg: strings.TrimPrefix(line, "upstream: ")}
	case line == "":
		return fmt.Errorf("mux master did not start")
	default:
		return fmt.Errorf("mux master: %s", line)
	}
}

// muxChildEnv drops the auth key: the master never opens the vault.
func muxChildEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "WRAPPER_AUTH_KEY=") {
			env = append(env, kv)
		}
	}
	return env
}

// runMuxMaster is the hidden --mux-master mode: dial upstream once, report
// readiness on fd 3, then serve until idle, stopped, or disconnected.
func runMuxMaster() {
	ready := os.NewFile(3, "ready")
	if ready == nil {
		os.Exit(2)
	}
	report := func(msg string) {
		fmt.Fprintln(ready, msg)
		ready.Close()
	}

	var spec muxMasterSpec
	if err := json.NewDecoder(os.Stdin).Decode(&spec); err != nil {
		report("bad spec")
		os.Exit(1)
	}

	upstream, err := connections.DialSSH(spec.Host, spec.Port, spec.Username, spec.Password, spec.KeyPath, spec.KeyPass)
	if err != nil {
		report("upstream: " + strings.ReplaceAll(err.Error(), "\n", " "))
		os.Exit(1)
	}

	ln, signer, err := connections.ListenMux(spec.Socket)
	if err != nil {
		upstream.Close()
		report(err.Error())
		os.Exit(1)
	}
	srv := &connections.MuxServer{Upstream: upstream, Token: spec.Token, Signer: signer, SocketPath: spec.Socket, Idle: spec.Persist}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		<-sigs
		ln.Close()
	}()

	report("ok")
	srv.Serve(ln)
}

// muxControl implements --mux-status and --mux-stop.
func muxControl(conn Connection, op string) {
	if !muxCapable(conn) {
		fmt.Fprintf(os.Stderr, "Error: connection \"%s\" is type %s, not SSH\n", conn.Name, conn.Type)
		os.Exit(1)
	}
	sock, token := muxSocketPath(conn), muxToken(conn)
	switch op {
	case "mux-status":
		c, err := connections.DialMux(sock, token)
		if err != nil {
			fmt.Println("No master running")
			os.Exit(1)
		}
		c.Close()
		fmt.Printf("Master running (%s)\n", sock)
	case "mux-stop":
		if err := connections.StopMux(sock, token); err != nil {
			fmt.Println("No master running")
			return
		}
		fmt.Println("Master stopped")
	}
}
