package xhttpstream

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const bufSize = 2048

// Writer is an encrypted io.Writer. It keeps one buffer so a plain Write does
// not allocate, exactly like the shadowsocks stream writer the vendor forked.
type Writer struct {
	io.Writer
	cipher.Stream
	buf [bufSize]byte

	access sync.Mutex
}

// NewWriter wraps an io.Writer with stream cipher encryption.
func NewWriter(w io.Writer, s cipher.Stream) *Writer {
	return &Writer{Writer: w, Stream: s}
}

func (w *Writer) Write(p []byte) (n int, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	buf := w.buf[:]
	for nw := 0; n < len(p) && err == nil; n += nw {
		end := n + len(buf)
		if end > len(p) {
			end = len(p)
		}
		w.XORKeyStream(buf, p[n:end])
		nw, err = w.Writer.Write(buf[:end-n])
	}
	return
}

func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	buf := w.buf[:]
	for {
		nr, er := r.Read(buf)
		n += int64(nr)
		b := buf[:nr]
		w.XORKeyStream(b, b)
		if _, err = w.Writer.Write(b); err != nil {
			return
		}
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			return
		}
	}
}

// Reader is an encrypted io.Reader.
type Reader struct {
	io.Reader
	cipher.Stream
	buf [bufSize]byte
}

// NewReader wraps an io.Reader with stream cipher decryption.
func NewReader(r io.Reader, s cipher.Stream) *Reader {
	return &Reader{Reader: r, Stream: s}
}

func (r *Reader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if err != nil {
		return 0, err
	}
	r.XORKeyStream(p, p[:n])
	return
}

func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	buf := r.buf[:]
	for {
		nr, er := r.Reader.Read(buf)
		if nr > 0 {
			r.XORKeyStream(buf, buf[:nr])
			nw, ew := w.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				err = ew
				return
			}
		}
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract
				err = er
			}
			return
		}
	}
}

// Conn is an xhttp transport stream.
//
// Wire format, client to server (confirmed against the vendor build):
//
//	[128]  forged prefix: hex(fake-net["tcp"]) followed by random bytes
//	[16]   token, md5(secret + "do not hack this protocol please")
//	[H]    hmac key, hex decoded from the second half of the password
//	[1]    IV length, 0x10 for AES-CTR
//	[IV]   random write IV
//	[..]   AES-CTR(SOCKS address of the first target)
//	[..]   AES-CTR(payload)
//
// Server to client (reconstructed; see the report's 联调 list):
//
//	[128]  forged prefix
//	[16]   the same token, echoed back (mismatch => ErrInvalidToken)
//	[1]    length N of the server preamble (padding in the vendor build)
//	[N]    preamble bytes, not used by the client
//	[1]    IV length
//	[IV]   read IV
type Conn struct {
	net.Conn
	Cipher
	r       *Reader
	w       *Writer
	readIV  []byte
	writeIV []byte

	// Destination is the SOCKS address written as the first encrypted bytes.
	Destination []byte
	token       []byte
	hmac        []byte
	paddingLen  int
	lock        sync.Mutex
	fakeNet     map[string]string
}

func (c *Conn) initReader() error {
	if c.r != nil {
		return nil
	}
	// Discard the server's forged prefix.
	if _, err := io.CopyN(io.Discard, c.Conn, FakePrefixLen); err != nil {
		return err
	}
	if len(c.token) > 0 {
		serverToken := make([]byte, len(c.token))
		if _, err := io.ReadFull(c.Conn, serverToken); err != nil {
			return err
		}
		if !tokenEqual(serverToken, c.token) {
			return ErrInvalidToken
		}
	}
	// The server preamble is length prefixed so the client does not need to
	// know how much padding it chose.
	preambleLen, err := readLengthByte(c.Conn)
	if err != nil {
		return err
	}
	if preambleLen > 0 {
		if _, err := io.CopyN(io.Discard, c.Conn, int64(preambleLen)); err != nil {
			return err
		}
	}
	ivLen, err := readLengthByte(c.Conn)
	if err != nil {
		return err
	}
	if ivLen != c.IVSize() {
		return fmt.Errorf("xhttp: unexpected read IV length %d (want %d)", ivLen, c.IVSize())
	}
	iv, err := c.ObtainReadIV(int(ivLen))
	if err != nil {
		return err
	}
	c.r = NewReader(c.Conn, c.Decrypter(iv))
	return nil
}

func (c *Conn) initWriter() error {
	if c.w != nil {
		return nil
	}
	iv, err := c.ObtainWriteIV()
	if err != nil {
		return err
	}
	fake, err := DecodeFakeNet(c.fakeNet, "tcp")
	if err != nil {
		return err
	}
	header := make([]byte, FakePrefixLen+len(c.token)+len(c.hmac)+1+len(iv))
	copied := copy(header[:FakePrefixLen], fake)
	if copied < FakePrefixLen {
		if _, err := rand.Read(header[copied:FakePrefixLen]); err != nil {
			return err
		}
	}
	offset := FakePrefixLen
	offset += copy(header[offset:], c.token)
	offset += copy(header[offset:], c.hmac)
	header[offset] = byte(len(iv))
	offset++
	copy(header[offset:], iv)
	if _, err := c.Conn.Write(header); err != nil {
		return err
	}
	c.w = NewWriter(c.Conn, c.Encrypter(iv))
	if len(c.Destination) > 0 {
		if _, err := c.w.Write(c.Destination); err != nil {
			return err
		}
	}
	return nil
}

// Read implements net.Conn.
func (c *Conn) Read(b []byte) (int, error) {
	if c.r == nil {
		c.lock.Lock()
		err := c.initReader()
		c.lock.Unlock()
		if err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

// Write implements net.Conn. A zero length write only forces the handshake,
// which is the mihomo EarlyConn convention for proxies that defer it.
func (c *Conn) Write(b []byte) (int, error) {
	if c.w == nil {
		c.lock.Lock()
		err := c.initWriter()
		c.lock.Unlock()
		if err != nil {
			return 0, err
		}
		if len(b) == 0 {
			return 0, nil
		}
	}
	return c.w.Write(b)
}

// WriteTo implements io.WriterTo.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		c.lock.Lock()
		err := c.initReader()
		c.lock.Unlock()
		if err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

// ReadFrom implements io.ReaderFrom.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		c.lock.Lock()
		err := c.initWriter()
		c.lock.Unlock()
		if err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

// NeedHandshake implements sing's network.EarlyConn, so callers that know the
// convention can force the handshake with a zero length write.
func (c *Conn) NeedHandshake() bool {
	return c.w == nil
}

// ObtainWriteIV returns the cached write IV, generating it on first use.
func (c *Conn) ObtainWriteIV() ([]byte, error) {
	if len(c.writeIV) == c.IVSize() {
		return c.writeIV, nil
	}
	iv := make([]byte, c.IVSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	c.writeIV = iv
	return iv, nil
}

// ObtainReadIV reads size bytes of IV from the connection, caching the result.
func (c *Conn) ObtainReadIV(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("xhttp: empty read IV")
	}
	if len(c.readIV) == size {
		return c.readIV, nil
	}
	iv := make([]byte, size)
	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return nil, err
	}
	c.readIV = iv
	return iv, nil
}

// SetPaddingLen records the configured padding range. The vendor build parses
// `padding-len` but never uses it on the client side; it is kept here so the
// option is not silently dropped.
func (c *Conn) SetPaddingLen(paddingLen int) {
	c.paddingLen = paddingLen
}

func readLengthByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// ParsePaddingLen accepts the vendor form "<min>-<max>" (for example "8-64"),
// a bare "<max>" or an empty string. The values are parsed for validation and
// kept on the connection; this build does not pad the client stream.
func ParsePaddingLen(value string) (minLen, maxLen int, err error) {
	if value == "" {
		return 0, 0, nil
	}
	parse := func(s string) (int, error) {
		var n int
		_, scanErr := fmt.Sscanf(s, "%d", &n)
		if scanErr != nil {
			return 0, fmt.Errorf("xhttp: invalid padding-len %q", value)
		}
		return n, nil
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '-' {
			continue
		}
		if minLen, err = parse(value[:i]); err != nil {
			return 0, 0, err
		}
		if maxLen, err = parse(value[i+1:]); err != nil {
			return 0, 0, err
		}
		if minLen < 0 || maxLen < minLen || maxLen > 1<<16 {
			return 0, 0, fmt.Errorf("xhttp: padding-len out of range %q", value)
		}
		return minLen, maxLen, nil
	}
	if maxLen, err = parse(value); err != nil {
		return 0, 0, err
	}
	if maxLen < 0 || maxLen > 1<<16 {
		return 0, 0, fmt.Errorf("xhttp: padding-len out of range %q", value)
	}
	return 0, maxLen, nil
}
