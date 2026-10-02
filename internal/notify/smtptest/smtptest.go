// Package smtptest is a minimal plaintext SMTP server that records messages,
// for testing the email channel.
package smtptest

import (
	"bufio"
	"net"
	"strings"
	"sync"
)

// Message is one received email.
type Message struct {
	From string
	To   []string
	Data string
}

// Server accepts SMTP sessions without TLS or authentication.
type Server struct {
	ln       net.Listener
	mu       sync.Mutex
	messages []Message
	notify   chan struct{}
	// RejectCode, if set, is returned for RCPT TO (e.g. "550" or "451").
	RejectCode string
}

// Start listens on addr ("127.0.0.1:0" for a random port).
func Start(addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln, notify: make(chan struct{}, 100)}
	go s.serve()
	return s, nil
}

// Addr returns the listening address.
func (s *Server) Addr() *net.TCPAddr { return s.ln.Addr().(*net.TCPAddr) }

// Close stops the server.
func (s *Server) Close() error { return s.ln.Close() }

// Messages returns the messages received so far.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

// Received is signaled after each message.
func (s *Server) Received() <-chan struct{} { return s.notify }

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.session(c)
	}
}

// address extracts the mailbox from "<a@b> PARAM=..." or "a@b".
func address(arg string) string {
	arg = strings.TrimSpace(arg)
	if i, j := strings.Index(arg, "<"), strings.Index(arg, ">"); i >= 0 && j > i {
		return arg[i+1 : j]
	}
	return strings.Fields(arg + " ")[0]
}

func (s *Server) session(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	reply := func(line string) { c.Write([]byte(line + "\r\n")) }
	reply("220 smtptest ESMTP")
	var m Message
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			reply("250-smtptest")
			reply("250 8BITMIME")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			m = Message{From: address(line[10:])}
			reply("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			if s.RejectCode != "" {
				reply(s.RejectCode + " rejected")
				continue
			}
			m.To = append(m.To, address(line[8:]))
			reply("250 OK")
		case cmd == "DATA":
			reply("354 go ahead")
			var data strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				data.WriteString(strings.TrimPrefix(l, "."))
			}
			m.Data = data.String()
			s.mu.Lock()
			s.messages = append(s.messages, m)
			s.mu.Unlock()
			select {
			case s.notify <- struct{}{}:
			default:
			}
			reply("250 queued")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 OK")
		}
	}
}
