package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

// maxLength is the maximum length of an unencrypted message.
const maxLength = (1 << 15) - 1 - box.Overhead

// minLength is the minimum length of an unencrypted message.
const minLength = 1

// A header encodes encrypted message length and nonce information. It is sent
// unencrypted at the start of the message. The length is used by the reader to
// ensure it has exactly enough data to decrypt the full message. Length is
// encoded as a signed 16-bit.
type header struct {
	Length int16
	Nonce  [24]byte
}

// A SecureReader reads encrypted messages from src and decrypts them using the
// key. Since decryption needs to be done on fixed length messages it contains a
// buffer to store any data not immediately read from the decrypted message.
// Future calls to Read() will read from this buffer until it is empty at which
// point a new message will be decrypted.
//
// *SecureReader implements the io.Reader() interface.
type SecureReader struct {
	src io.Reader
	key *[32]byte
	buf *bytes.Reader
}

// A SecureWriter encrypts messages using the key and writes them to dst.
//
// *SecureWriter implements the io.Writer() interface.
type SecureWriter struct {
	dst io.Writer
	key *[32]byte
}

// newHeader creates a header for a message with an unencrypted length of l. The
// nonce will be generated from rand.Reader.
func newHeader(length int) (*header, error) {
	if length > maxLength {
		return nil, fmt.Errorf("message size (%d) is larger than %d bytes", length, maxLength)
	}
	if length < minLength {
		return nil, fmt.Errorf("message size (%d) is smaller than %d bytes", length, minLength)
	}
	h := new(header)
	h.Length = int16(length) + box.Overhead
	if _, err := io.ReadFull(rand.Reader, h.Nonce[:]); err != nil {
		return nil, err
	}
	return h, nil
}

// WriteTo serialises the header and writes it out. It returns the number of
// bytes written and conforms to the io.WriteTo() interface.
func (h *header) WriteTo(w io.Writer) (int64, error) {
	b := new(bytes.Buffer)
	if err := binary.Write(b, binary.LittleEndian, h); err != nil {
		return 0, err
	}
	n, err := w.Write(b.Bytes())
	return int64(n), err
}

// ReadHeader deserialises a header read from the given io.Reader.
func ReadHeader(r io.Reader) (*header, error) {
	h := new(header)
	return h, binary.Read(r, binary.LittleEndian, h)
}

// Read implements the standard Read interface. It will read up to len(b) bytes
// of unencrypted data into b. To do this it must read the entire underlying
// encrypted message and will block until it is able to do so, or an error
// occurs. If it is unable to decrypt the message an error will be returned.
func (p *SecureReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Check to see if there are still remnants of the last message to read.
	if p.buf.Len() > 0 {
		return p.buf.Read(b)
	}

	// Read header from stream.
	h, err := ReadHeader(p.src)
	if err != nil {
		return 0, err
	}

	// Read the encrypted message.
	e := make([]byte, h.Length)
	if _, err := io.ReadFull(p.src, e); err != nil {
		return 0, err
	}

	// Decrypt message into d and check it is authentic. Limit the capacity of b
	// so that the Open...() function can't overwrite bytes > len(b).
	d, a := box.OpenAfterPrecomputation(b[:0:len(b)], e[:], &h.Nonce, p.key)
	if !a {
		return 0, fmt.Errorf("message failed authentication")
	}

	// Check to see if the underlying arrays are the same for b & d slices - if
	// they are then we don't need to copy OR buffer anything as implicitly
	// len(d) <= len(b).
	if &d[0] != &b[0] {
		copy(b, d)
		if len(d) > len(b) {
			p.buf = bytes.NewReader(d[len(b):])
			return len(b), nil
		}
	}
	return len(d), nil
}

// Write implements the standard write interface.
// Generate a header and write it out. Then encrypt and write out the message.
// Will only return less than len(b) if the error != nil.
func (p *SecureWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Send b in chunks such that we only send at most maxLength bytes at a time
	for i := 0; i < len(b); i += maxLength {
		l := i + maxLength
		if l > len(b) {
			l = len(b)
		}
		h, err := newHeader(len(b[i:l]))
		if err != nil {
			return i, err
		}
		if _, err := h.WriteTo(p.dst); err != nil {
			return i, err
		}
		e := box.SealAfterPrecomputation(nil, b[i:l], &h.Nonce, p.key)
		if _, err := p.dst.Write(e); err != nil {
			return i, err
		}
	}
	return len(b), nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	sr := SecureReader{src: r, key: new([32]byte), buf: bytes.NewReader(nil)}
	box.Precompute(sr.key, pub, priv)
	return &sr
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	sw := SecureWriter{dst: w, key: new([32]byte)}
	box.Precompute(sw.key, pub, priv)
	return &sw
}

// exchgKeys generates a public/private key pair and swaps the public key with
// its counterpart over rw. Returns the private key generated and the public
// key of its counterpart.
func exchgKeys(rw io.ReadWriter) (priv, peer *[32]byte, err error) {
	// Always return nil for the keys if there is an error
	defer func() {
		if err != nil {
			priv, peer = nil, nil
		}
	}()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	// Send our public key
	senderr := make(chan error)
	go func() {
		_, err := rw.Write(pub[:])
		senderr <- err
	}()
	defer func() {
		if err == nil {
			err = <-senderr
		}
	}()

	// Receive partner's public key
	peer = new([32]byte)
	_, err = io.ReadFull(rw, peer[:])
	return
}

// Dial generates a private/public key pair, connects to the server, perform the
// handshake and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	priv, pub, err := exchgKeys(conn)
	if err != nil {
		return nil, err
	}
	r := NewSecureReader(conn, priv, pub)
	w := NewSecureWriter(conn, priv, pub)
	return struct {
		io.Reader
		io.Writer
		io.Closer
	}{r, w, conn}, nil
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
			priv, pub, err := exchgKeys(conn)
			if err != nil {
				return
			}
			r := NewSecureReader(conn, priv, pub)
			w := NewSecureWriter(conn, priv, pub)
			if _, err := io.Copy(w, r); err != nil {
				return
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
