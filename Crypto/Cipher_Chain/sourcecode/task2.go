package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"golang.org/x/crypto/curve25519"
)

const (
	Task1Answer = "aGFjyHX1aWdadade"
	RealFlag    = "SCTF{curve25519_bsuiahduie_cif_diqw}"
)

func deriveSecret(task1 string) [32]byte {
	seed := sha256.Sum256([]byte(task1))

	for i := 0; i < 50000; i++ {
		seed = sha256.Sum256(seed[:])
	}

	var sk [32]byte
	copy(sk[:], seed[:])
	return sk
}

func main() {

	sk := deriveSecret(Task1Answer)

	otherPub := [32]byte{
		0x32, 0x45, 0x12, 0x87, 0xAB, 0xCD, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
		0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
	}

	shared, _ := curve25519.X25519(sk[:], otherPub[:])

	k1 := sha256.Sum256(shared)
	k2 := sha256.Sum256(k1[:])

	flagBytes := []byte(RealFlag)
	enc := make([]byte, len(flagBytes))
	for i := range flagBytes {
		enc[i] = flagBytes[i] ^ k2[i%32]
	}

	os.WriteFile("task2.pub", otherPub[:], 0644)
	os.WriteFile("task2.enc", enc, 0644)

	logStr := "session_prefix = " + hex.EncodeToString(k1[:8]) + "\n"
	os.WriteFile("task2.log", []byte(logStr), 0644)

	println("生成文件:task2.pub  task2.enc  task2.log")
	println("Flag:", RealFlag)
}
