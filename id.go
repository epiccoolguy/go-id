package id

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"go.loafoe.dev/bitfield/v2"
)

type LDID struct {
	bf *bitfield.BitField
}

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
	var id = &LDID{
		bf: bitfield.BigEndian.New(128),
	}

	// Unix Timestamp (48 bits, 0-47)
	timestamp := g.GenerateUnixTimestampMS()
	if err := id.bf.InsertUint64(0, 48, timestamp); err != nil {
		return &LDID{}, err
	}

	// Version (4 bits, 48-51)
	version := uint64(0b0111)
	if err := id.bf.InsertUint64(48, 4, version); err != nil {
		return &LDID{}, err
	}

	// Pseudo-random data A (12 bits, 52-63)
	randA, err := g.GenerateRandomBits(12)
	if err != nil {
		return &LDID{}, err
	}
	if err := id.bf.InsertUint64(52, 12, randA); err != nil {
		return &LDID{}, err
	}

	// Variant (2 bits, 64-65)
	variant := uint64(0b10)
	if err := id.bf.InsertUint64(64, 2, variant); err != nil {
		return &LDID{}, err
	}

	// Pseudo-random data B (62 bits, 66-127)
	randB, err := g.GenerateRandomBits(62)
	if err != nil {
		return &LDID{}, err
	}
	if err := id.bf.InsertUint64(66, 62, randB); err != nil {
		return &LDID{}, err
	}

	return id, nil
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
	bytes := id.bf.Bytes()
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:])
}

func (id *LDID) Timestamp() (uint64, error) {
	return id.bf.ExtractUint64(0, 48)
}

func (id *LDID) Version() (uint64, error) {
	return id.bf.ExtractUint64(48, 4)
}

func (id *LDID) RandA() (uint64, error) {
	return id.bf.ExtractUint64(52, 12)
}

func (id *LDID) Variant() (uint64, error) {
	return id.bf.ExtractUint64(64, 2)
}

func (id *LDID) RandB() (uint64, error) {
	return id.bf.ExtractUint64(66, 62)
}
