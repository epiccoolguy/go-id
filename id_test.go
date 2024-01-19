package id

import (
	"errors"
	"regexp"
	"testing"
)

type MockGenerator struct {
	*DefaultGenerator           // Embed the default generator so we only have to override methods we care about
	GenerateUnixTimestampMSFunc func() uint64
	GenerateRandomBitsFunc      func(n int64) (uint64, error)
}

// Compile-time check to ensure MockGenerator implements Generator
var _ Generator = &MockGenerator{}

func (m *MockGenerator) GenerateUnixTimestampMS() uint64 {
	if m.GenerateUnixTimestampMSFunc != nil {
		return m.GenerateUnixTimestampMSFunc()
	}
	return m.DefaultGenerator.GenerateUnixTimestampMS()
}

func (m *MockGenerator) GenerateRandomBits(n int64) (uint64, error) {
	if m.GenerateRandomBitsFunc != nil {
		return m.GenerateRandomBitsFunc(n)
	}
	return m.DefaultGenerator.GenerateRandomBits(n)
}

func TestNewWithGenerator(t *testing.T) {
	t.Run("Timestamp", func(t *testing.T) {
		expectedTimestamp := uint64(0b111111111111111111111111111111111111111111111111) // 48 bits

		m := &MockGenerator{
			GenerateUnixTimestampMSFunc: func() uint64 {
				return 0b1111111111111111111111111111111111111111111111111111111111111111 // 64 bits
			},
		}

		ldid, err := NewWithGenerator(m)

		if err != nil {
			t.Fatalf("New() error = %v, wantErr %v", err, false)
			return
		}

		if timestamp, _ := ldid.GetTimestamp(); timestamp != expectedTimestamp {
			t.Fatalf("GetTimestamp() = %v, want %v", timestamp, expectedTimestamp)
		}
	})

	t.Run("Version", func(t *testing.T) {
		expectedVersion := uint64(0b0111)

		ldid, err := NewWithGenerator(&DefaultGenerator{})

		if err != nil {
			t.Fatalf("New() error = %v, wantErr %v", err, false)
			return
		}

		if version, _ := ldid.GetVersion(); version != expectedVersion {
			t.Fatalf("GetVersion() = %v, want %v", version, expectedVersion)
		}
	})

	t.Run("Random data", func(t *testing.T) {
		expectedRandA := uint64(0b000011110000)                                                   // 12 bits
		expectedRandB := uint64(0b11000011110000111100001111000011110000111100001111000011110000) // 62 bits

		m := &MockGenerator{
			GenerateRandomBitsFunc: func(n int64) (uint64, error) {
				return 0b1111000011110000111100001111000011110000111100001111000011110000, nil
			},
		}

		ldid, err := NewWithGenerator(m)

		if err != nil {
			t.Fatalf("New() error = %v, wantErr %v", err, false)
			return
		}

		if randA, _ := ldid.GetRandA(); randA != expectedRandA {
			t.Fatalf("GetRandA() = %v, want %v", randA, expectedRandA)
		}

		if randB, _ := ldid.GetRandB(); randB != expectedRandB {
			t.Fatalf("GetRandB() = %v, want %v", randB, expectedRandB)
		}
	})

	t.Run("Variant", func(t *testing.T) {
		expectedVariant := uint64(0b10)

		ldid, err := NewWithGenerator(&DefaultGenerator{})

		if err != nil {
			t.Fatalf("New() error = %v, wantErr %v", err, false)
			return
		}

		if variant, _ := ldid.GetVariant(); variant != expectedVariant {
			t.Fatalf("GetVariant() = %v, want %v", variant, expectedVariant)
		}
	})

	t.Run("GenerateRandomBits failing", func(t *testing.T) {
		m := &MockGenerator{
			GenerateRandomBitsFunc: func(n int64) (uint64, error) {
				return 0, errors.New("mock error")
			},
		}

		_, err := NewWithGenerator(m)

		if err == nil {
			t.Fatalf("NewWithGenerator() error = %v, wantErr true", err)
		}
	})
}

func TestNew(t *testing.T) {
	t.Run("Default generator", func(t *testing.T) {
		ldid, err := New()

		if err != nil {
			t.Fatalf("New() error = %v, wantErr %v", err, false)
			return
		}

		if ldid == nil {
			t.Fatalf("New() = %v, want non-nil", ldid)
		}
	})
}

func TestString(t *testing.T) {
	ldid, err := New()
	if err != nil {
		t.Fatalf("New() error = %v, wantErr %v", err, false)
	}

	str := ldid.String()

	// Check if the output is a valid UUID-like string
	match, _ := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, str)
	if !match {
		t.Fatalf("String() = %v, want a valid UUID-like string", str)
	}
}
