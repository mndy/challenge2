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

func generateNonce(nonce *[24]byte) error {
	_, err := io.ReadFull(rand.Reader, nonce[:])
	return err
}

func (p secureReader) Read(b []byte) (int, error) {
	if p.buf == nil {
		var h header
		if err := binary.Read(p.src, binary.LittleEndian, &h); err != nil {
			return 0, err
		}

		p.buf = make([]byte, h.Length-secretbox.Overhead)
		tmp := make([]byte, h.Length)

		if _, err := io.ReadFull(p.src, tmp); err != nil {
			return 0, err
		}

		_, auth := secretbox.Open(p.buf[:0], tmp[:], &h.Nonce, p.key)
		if !auth {
			return 0, fmt.Errorf("Message failed authentication")
		}
	}
	var size int
	if len(b) >= len(p.buf) {
		size = len(p.buf)
	} else {
		size = len(b)
	}

	for i := 0; i < size; i++ {
		b[i] = p.buf[i]
	}

	if size == len(p.buf) {
		p.buf = nil
	} else {
		p.buf = p.buf[size:]
	}
	return size, nil
}

func (p secureWriter) Write(b []byte) (int, error) {
	var h header
	h.Length = uint64(len(b) + secretbox.Overhead)
	if err := generateNonce(&h.Nonce); err != nil {
		return 0, err
	}

	hbuf := new(bytes.Buffer)
	binary.Write(hbuf, binary.LittleEndian, &h)
	if _, err := p.dst.Write(hbuf.Bytes()); err != nil {
		return 0, err
	}

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

func swapKeys(r io.Reader, w io.Writer) (priv, pub, peer *[32]byte, err error) {
	pub, priv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	sent := make(chan error)
	defer close(sent)

	go func() {
		_, err := w.Write(pub[:])
		sent <- err
	}()

	peer = new([32]byte)
	_, err = io.ReadFull(r, peer[:])
	if err != nil {
		return nil, nil, nil, err
	}

	if err = <-sent; err != nil {
		return nil, nil, nil, err
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

	priv, _, servpub, err := swapKeys(conn, conn)
	if err != nil {
		return nil, err
	}

	secconn := struct {
		io.Reader
		io.Writer
		io.Closer
	}{
		NewSecureReader(conn, priv, servpub),
		NewSecureWriter(conn, priv, servpub),
		conn,
	}

	return secconn, nil
}

func connect(c net.Conn) {
	defer c.Close()

	priv, _, clientpub, err := swapKeys(c, c)
	if err != nil {
		log.Fatal(err)
	}

	r := NewSecureReader(c, priv, clientpub)
	w := NewSecureWriter(c, priv, clientpub)

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
