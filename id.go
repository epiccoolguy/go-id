package id

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"go.loafoe.dev/bitfield/v2"
)

// Constants defining the size and offset of various fields in an LDID.
const (
	timestampSize   uint64 = 48 // Size of the timestamp field in bits.
	timestampOffset uint64 = 0  // Offset of the timestamp field in bits.
	versionSize     uint64 = 4  // Size of the version field in bits.
	versionOffset   uint64 = 48 // Offset of the version field in bits.
	randASize       uint64 = 12 // Size of the random data A field in bits.
	randAOffset     uint64 = 52 // Offset of the random data A field in bits.
	variantSize     uint64 = 2  // Size of the variant field in bits.
	variantOffset   uint64 = 64 // Offset of the variant field in bits.
	randBSize       uint64 = 62 // Size of the random data B field in bits.
	randBOffset     uint64 = 66 // Offset of the random data B field in bits.
)

type LDID struct {
	bf *bitfield.BitField
}

type Generator interface {
	GenerateUnixTimestampMS() uint64
	GenerateRandomBits(randReader io.Reader, n int64) (uint64, error)
}

type DefaultGenerator struct{}

var defaultGenerator Generator = &DefaultGenerator{}

func (g *DefaultGenerator) GenerateUnixTimestampMS() uint64 {
	return uint64(time.Now().UnixMilli())
}

func (g *DefaultGenerator) GenerateRandomBits(randReader io.Reader, n int64) (r uint64, err error) {
	// rand.Int can panic if n <= 0, so we need to recover from that
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("crypto/rand: %v", r)
		}
	}()

	max := &big.Int{}
	max.Exp(big.NewInt(2), big.NewInt(n), nil).Sub(max, big.NewInt(1)) // 2^n-1

	if !max.IsUint64() {
		return 0, errors.New("failed to generate random bits: n is too large to fit in a uint64")
	}

	rb, err := rand.Int(randReader, max)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random bits: %w", err)
	}

	return rb.Uint64(), nil
}

// NewWithGenerator creates a new LDID with a provided generator
func NewWithGenerator(g Generator) (*LDID, error) {
	var id = &LDID{
		bf: bitfield.BigEndian.New(128),
	}

	// Unix Timestamp (48 bits, 0-47)
	timestamp := g.GenerateUnixTimestampMS()
	// Version (4 bits, 48-51)
	version := uint64(0b0111)
	// Pseudo-random data A (12 bits, 52-63)
	randA, err := g.GenerateRandomBits(rand.Reader, 12)
	if err != nil {
		return &LDID{}, err
	}
	// Variant (2 bits, 64-65)
	variant := uint64(0b10)
	// Pseudo-random data B (62 bits, 66-127)
	randB, err := g.GenerateRandomBits(rand.Reader, 62)
	if err != nil {
		return &LDID{}, err
	}

	id.bf.InsertUint64(timestampOffset, timestampSize, timestamp)
	id.bf.InsertUint64(versionOffset, versionSize, version)
	id.bf.InsertUint64(randAOffset, randASize, randA)
	id.bf.InsertUint64(variantOffset, variantSize, variant)
	id.bf.InsertUint64(randBOffset, randBSize, randB)

	if err := id.bf.Error(); err != nil {
		return &LDID{}, err
	}

	return id, nil
}

// New creates a new LDID with the default generator
func New() (*LDID, error) {
	// Use the default when creating a new LDID
	return NewWithGenerator(defaultGenerator)
}

// parseUUIDString parses a canonical UUID string into a byte slice.
func parseUUIDString(s string) ([]byte, error) {
	// Remove hyphens from the string
	s = strings.ReplaceAll(s, "-", "")

	// Convert the string to bytes
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// FromString parses the canonical string representation of a UUID into a new LDID.
func FromString(s string) (*LDID, error) {
	bytes, err := parseUUIDString(s)
	if err != nil {
		return &LDID{}, err
	}

	bf := bitfield.BigEndian.FromBytes(bytes, uint64(len(bytes)))

	ldid := &LDID{
		bf: bf,
	}

	return ldid, nil
}

// String formats the LDID bytes into the canonical string representation of a UUID.
func (id *LDID) String() string {
	bytes := id.bf.Bytes()
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:])
}

// Bytes returns the raw bytes of the LDID.
func (id *LDID) Bytes() []byte {
	return id.bf.Bytes()
}

func (id *LDID) Timestamp() (uint64, error) {
	return id.bf.ExtractUint64(timestampOffset, timestampSize)
}

func (id *LDID) Version() (uint64, error) {
	return id.bf.ExtractUint64(versionOffset, versionSize)
}

func (id *LDID) RandA() (uint64, error) {
	return id.bf.ExtractUint64(randAOffset, randASize)
}

func (id *LDID) Variant() (uint64, error) {
	return id.bf.ExtractUint64(variantOffset, variantSize)
}

func (id *LDID) RandB() (uint64, error) {
	return id.bf.ExtractUint64(randBOffset, randBSize)
}
