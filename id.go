package id

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"go.loafoe.dev/bitfield/v2"
)

type LDID [16]byte // Fixed-size byte slice holding the UUID.

type Generator interface {
	GenerateUnixTimestampMS() uint64
	GenerateRandomBits(n int64) (uint64, error)
}

type DefaultGenerator struct{}

// Compile-time check to ensure DefaultGenerator implements Generator
var _ Generator = &DefaultGenerator{}

func (g *DefaultGenerator) GenerateUnixTimestampMS() uint64 {
	return uint64(time.Now().UnixMilli())
}

func (g *DefaultGenerator) GenerateRandomBits(n int64) (uint64, error) {
	max := &big.Int{}
	max.Exp(big.NewInt(2), big.NewInt(n), nil).Sub(max, big.NewInt(1)) // 2^n-1

	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}

	return r.Uint64(), nil
}

// NewWithGenerator creates a new LDID with a provided generator
func NewWithGenerator(g Generator) (*LDID, error) {
	bf := bitfield.BigEndian.New(128)

	// Unix Timestamp (48 bits, 0-47)
	timestamp := g.GenerateUnixTimestampMS()
	if err := bf.InsertUint64(0, 48, timestamp); err != nil {
		return &LDID{}, err
	}

	// Version (4 bits, 48-51)
	version := uint64(0b0111)
	if err := bf.InsertUint64(48, 4, version); err != nil {
		return &LDID{}, err
	}

	// Pseudo-random data A (12 bits, 52-63)
	randA, err := g.GenerateRandomBits(12)
	if err != nil {
		return &LDID{}, err
	}
	if err := bf.InsertUint64(52, 12, randA); err != nil {
		return &LDID{}, err
	}

	// Variant (2 bits, 64-65)
	variant := uint64(0b10)
	if err := bf.InsertUint64(64, 2, variant); err != nil {
		return &LDID{}, err
	}

	// Pseudo-random data B (62 bits, 66-127)
	randB, err := g.GenerateRandomBits(62)
	if err != nil {
		return &LDID{}, err
	}
	if err := bf.InsertUint64(66, 62, randB); err != nil {
		return &LDID{}, err
	}

	var ldid LDID

	b := bf.Bytes()
	copy(ldid[:], b[:16])

	return &ldid, nil
}

// New creates a new LDID with the default generator
func New() (*LDID, error) {
	// Create an instance of DefaultGenerator
	defaultGen := &DefaultGenerator{}

	// Use the default when creating a new LDID
	return NewWithGenerator(defaultGen)
}

// String formats the UUID bytes into the canonical string representation.
func (id *LDID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func (id *LDID) GetTimestamp() (uint64, error) {
	bf := bitfield.BigEndian.FromBytes(id[:], 128)
	return bf.ExtractUint64(0, 48)
}

func (id *LDID) GetVersion() (uint64, error) {
	bf := bitfield.BigEndian.FromBytes(id[:], 128)
	return bf.ExtractUint64(48, 4)
}

func (id *LDID) GetRandA() (uint64, error) {
	bf := bitfield.BigEndian.FromBytes(id[:], 128)
	return bf.ExtractUint64(52, 12)
}

func (id *LDID) GetVariant() (uint64, error) {
	bf := bitfield.BigEndian.FromBytes(id[:], 128)
	return bf.ExtractUint64(64, 2)
}

func (id *LDID) GetRandB() (uint64, error) {
	bf := bitfield.BigEndian.FromBytes(id[:], 128)
	return bf.ExtractUint64(66, 62)
}
