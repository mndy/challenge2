package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
	"net"
	"os"
)

// Calculate maximum signed integer
// https://groups.google.com/forum/#!msg/golang-nuts/a9PitPAHSSU/ziQw1-QHw3EJ
const maxInt = int(^uint(0) >> 1)

// A header encodes encrypted message length and nonce information. It is
// sent unencrypted at the start of the message. The length is used by the
// reader to ensure it has exactly enough data to decrypt the full message.
//
// Length is encoded as an unsigned 64 bit value to ensure correctness
// between 32 bit and 64 bit machines.
type header struct {
	Length uint64
	Nonce  [24]byte
}

// A SecureReader reads encrypted messages from src and decrypts them using
// the key. Since decryption needs to be done on fixed length messages it
// contains a buffer to store any data not immediately read from the
// decrypted message. Future calls to Read() will read from this buffer
// until it is empty at which point a new message will be decrypted.
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

// Creates a new header for a message with an unencrypted length of l. The nonce
// will be generated from rand.Reader.
func newHeader(l int) (*header, error) {
	h := new(header)
	h.Length = uint64(l) + box.Overhead
	if err := h.CheckLength(); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, h.Nonce[:]); err != nil {
		return nil, err
	}
	return h, h.CheckLength()
}

// Serialise the header and write it out.
func (h *header) WriteTo(w io.Writer) (n int64, err error) {
	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.LittleEndian, h); err != nil {
		return
	}

	nint, err := w.Write(b.Bytes())
	n = int64(nint)
	return
}

// The encrypted length of the message
func (h *header) EncryptedLen() int {
	return int(h.Length)
}

// The length the message will be after it has been decrypted
func (h *header) DecryptedLen() int {
	return int(h.Length - box.Overhead)
}

// Check that the encrypted message length fits within an int on this machine.
// Potentially important when mixing 32 and 64 bit machines.
func (h *header) CheckLength() error {
	if h.Length > uint64(maxInt) {
		return fmt.Errorf("Message length (%d) is out of range (max is %d)", h.Length, maxInt)
	}
	return nil
}

// Read in a header. Check if the header length fits into an int so we
// don't have to check elsewhere.
func ReadHeader(r io.Reader) (h header, err error) {
	err = binary.Read(r, binary.LittleEndian, &h)
	if err == nil {
		err = h.CheckLength()
	}
	return
}

func (p *SecureReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Check to see if there are still remnants of the last message to
	// read
	if p.buf.Len() > 0 {
		return p.buf.Read(b)
	}

	// Read header from stream
	h, err := ReadHeader(p.src)
	if err != nil {
		return 0, err
	}

	// Read the encrypted message
	tmp := make([]byte, h.EncryptedLen())
	if _, err := io.ReadFull(p.src, tmp); err != nil {
		return 0, err
	}

	// Decrypt message and check it is authentic
	d, auth := box.OpenAfterPrecomputation(nil, tmp[:], &h.Nonce, p.key)
	if !auth {
		return 0, fmt.Errorf("Message failed authentication")
	}

	// Can avoid this copy by passing b into box.Open() if we have enough data
	// However interface to box.Open() does not guarantee that it will not write
	// to bytes between [len(b), cap(b)).
	copy(b, d)
	if len(b) < len(d) {
		p.buf = bytes.NewReader(d[len(b):])
		return len(b), nil
	}

	return len(d), nil
}

func (p *SecureWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	h, err := newHeader(len(b))
	if err != nil {
		return 0, nil
	}
	if _, err := h.WriteTo(p.dst); err != nil {
		return 0, err
	}

	tmp := box.SealAfterPrecomputation(nil, b, &h.Nonce, p.key)
	if _, err := p.dst.Write(tmp); err != nil {
		return 0, err
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

// Generate a public/private key pair. Swap public keys over ReadWriter.
// Return our private key and our partner's public key.
func swapKeys(rw io.ReadWriter) (priv, peer *[32]byte, err error) {
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

	// Send
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

	// Receive
	peer = new([32]byte)
	_, err = io.ReadFull(rw, peer[:])

	return
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (rwc io.ReadWriteCloser, err error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}

	priv, pub, err := swapKeys(conn)
	if err != nil {
		return
	}

	r := NewSecureReader(conn, priv, pub)
	w := NewSecureWriter(conn, priv, pub)
	rwc = struct {
		io.Reader
		io.Writer
		io.Closer
	}{r, w, conn}

	return
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
