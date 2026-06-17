package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
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
	var ans string
	fmt.Print("输入Task1答案:")
	fmt.Scanln(&ans)

	sk := deriveSecret(ans)
	otherPub, err := os.ReadFile("task2.pub")
	if err != nil {
		panic(err)
	}

	enc, err := os.ReadFile("task2.enc")
	if err != nil {
		panic(err)
	}

	fmt.Println("pub len:", len(otherPub))
	fmt.Println("enc len:", len(enc))

	shared, err := curve25519.X25519(sk[:], otherPub)
	if err != nil {
		panic(err)
	}

	k1 := sha256.Sum256(shared)
	fmt.Println("k1 prefix:", hex.EncodeToString(k1[:8]))

	k2 := sha256.Sum256(k1[:])

	flag := make([]byte, len(enc))
	for i := range enc {
		flag[i] = enc[i] ^ k2[i%32]
	}

	fmt.Println("解密成功：", string(flag))
}
