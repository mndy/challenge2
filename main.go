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

// A header encodes encrypted message length and nonce information. It is
// sent unencrypted at the start of the message. The length is used by the
// reader to ensure it has exactly enough data to decrypt the full message.
type header struct {
	Length uint64
	Nonce  [24]byte
}

// A secureReader reads encrypted messages from src and decrypts them using
// the key. Since decryption needs to be done on fixed length messages it
// contains a buffer to store any data not immediately read from the
// decrypted message. Future calls to Read() will read from this buffer
// until it is empty at which point a new message will be decrypted.
type secureReader struct {
	src io.Reader
	key *[32]byte
	buf []byte
}

// A secureWriter encrypts messages using the key and writes them to dst.
type secureWriter struct {
	dst io.Writer
	key *[32]byte
}

func (p secureReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Check to see if there are still remnants of the last message to
	// read
	if p.buf == nil {
		// Read header from stream
		var h header
		if err := binary.Read(p.src, binary.LittleEndian, &h); err != nil {
			return 0, err
		}

		// Read the encrypted message
		tmp := make([]byte, h.Length)
		if _, err := io.ReadFull(p.src, tmp); err != nil {
			return 0, err
		}

		// Decrypt message and check it is authentic
		p.buf = make([]byte, h.Length-secretbox.Overhead)
		if _, auth := secretbox.Open(p.buf[:0], tmp[:], &h.Nonce, p.key); !auth {
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
	if len(b) == 0 {
		return 0, nil
	}

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
	if _, err := p.dst.Write(tmp); err != nil {
		return 0, err
	}
	return len(b), nil
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

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()

			priv, pub, err := swapKeys(conn)
			if err != nil {
				log.Fatal(err)
			}

			r := NewSecureReader(conn, priv, pub)
			w := NewSecureWriter(conn, priv, pub)

			if _, err := io.Copy(w, r); err != nil {
				log.Fatal(err)
			}
		}()
	}
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
