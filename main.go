package challenge2

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
	"log"
	"net"
	"os"
)

var readNonce [24]byte
var writeNonce [24]byte

type secureReader struct {
	src io.Reader
	key *[32]byte
}

type secureWriter struct {
	dst io.Writer
	key *[32]byte
}

func increment(nonce *[24]byte) {
	for i := range nonce {
		nonce[i] += 1
		if nonce[i] != 0 {
			break
		}
	}
}

func (p secureReader) Read(b []byte) (int, error) {
	increment(&readNonce)
	tmp := make([]byte, len(b)+secretbox.Overhead)
	n, err := p.src.Read(tmp)
	secretbox.Open(b[:0], tmp[:n], &readNonce, p.key) // Deal with error!
	return n - box.Overhead, err
}

func (p secureWriter) Write(b []byte) (int, error) {
	increment(&writeNonce)
	tmp := make([]byte, len(b)+secretbox.Overhead)
	tmp = secretbox.Seal(tmp[:0], b, &writeNonce, p.key)
	sent := 0
	for sent < len(tmp) {
		n, _ := p.dst.Write(tmp[sent:]) // Deal with error!
		sent += n
	}
	return sent, nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	sr := secureReader{src: r, key: new([32]byte)}
	box.Precompute(sr.key, pub, priv)
	return sr
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	sw := secureWriter{dst: w, key: new([32]byte)}
	box.Precompute(sw.key, pub, priv)
	return sw
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
