package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
	"log"
	"net"
	"os"
)

// header encodes encrypted message length and nonce information.
// It is sent unencrypted at the start of the message.
// The length is used to ensure we read enough data to decrypt the
// fix length message.
type header struct {
	Length uint64
	Nonce  [24]byte
}

type secureReader struct {
	src io.Reader
	key *[32]byte
	buf []byte
}

type secureWriter struct {
	dst io.Writer
	key *[32]byte
}

func (p secureReader) Read(b []byte) (int, error) {
	// Check to see if there are still remnants of the last message to
	// read
	if p.buf == nil {
		// Read header from stream
		var h header
		if err := binary.Read(p.src, binary.LittleEndian, &h); err != nil {
			return 0, err
		}

		// Allocate a buffer to contain the encrypted and decrypted message
		p.buf = make([]byte, h.Length-secretbox.Overhead)
		tmp := make([]byte, h.Length)

		// Read the encrypted message
		if _, err := io.ReadFull(p.src, tmp); err != nil {
			return 0, err
		}

		// Decrypt message and check it is authentic
		_, auth := secretbox.Open(p.buf[:0], tmp[:], &h.Nonce, p.key)
		if !auth {
			return 0, fmt.Errorf("Message failed authentication")
		}
	}

	// Copy the result into the output buffer, leaving a partial result
	// in the buffer if needed
	size := copy(b, p.buf)
	if size == len(p.buf) {
		p.buf = nil
	} else {
		p.buf = p.buf[size:]
	}
	return size, nil
}

func (p secureWriter) Write(b []byte) (int, error) {
	// Encode header containing length and randomly generated nonce
	var h header
	h.Length = uint64(len(b) + secretbox.Overhead)
	if _, err := io.ReadFull(rand.Reader, h.Nonce[:]); err != nil {
		return 0, err
	}

	// Write header out
	hbuf := new(bytes.Buffer)
	binary.Write(hbuf, binary.LittleEndian, &h)
	if _, err := p.dst.Write(hbuf.Bytes()); err != nil {
		return 0, err
	}

	// Encrypt and send the message
	tmp := make([]byte, h.Length)
	secretbox.Seal(tmp[:0], b, &h.Nonce, p.key)
	return p.dst.Write(tmp)
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	sr := secureReader{src: r, key: new([32]byte), buf: nil}
	box.Precompute(sr.key, pub, priv)
	return sr
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	sw := secureWriter{dst: w, key: new([32]byte)}
	box.Precompute(sw.key, pub, priv)
	return sw
}

// Generate a public/private key pair.
// Swap public keys over ReadWriter.
func swapKeys(rw io.ReadWriter) (priv, peer *[32]byte, err error) {
	// Generate our public/private key pair
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Send our public key
	senderr := make(chan error)
	go func() {
		_, err := rw.Write(pub[:])
		senderr <- err
	}()

	// Receive their public key
	peer = new([32]byte)
	_, err = io.ReadFull(rw, peer[:])
	if err != nil {
		return nil, nil, err
	}

	// Wait for our send to complete
	if err = <-senderr; err != nil {
		return nil, nil, err
	}

	return
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	priv, pub, err := swapKeys(conn)
	if err != nil {
		return nil, err
	}

	return struct {
		io.Reader
		io.Writer
		io.Closer
	}{
		NewSecureReader(conn, priv, pub),
		NewSecureWriter(conn, priv, pub),
		conn,
	}, nil
}

func connect(conn net.Conn) {
	defer conn.Close()

	priv, pub, err := swapKeys(conn)
	if err != nil {
		log.Fatal(err)
	}

	r := NewSecureReader(conn, priv, pub)
	w := NewSecureWriter(conn, priv, pub)

	buf := make([]byte, 2048)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
		}
		if err == io.EOF {
			return
		}
	}
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go connect(conn)
	}
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
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
