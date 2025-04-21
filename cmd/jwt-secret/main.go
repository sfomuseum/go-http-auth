package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
	"-_"

var seededRand *rand.Rand = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), uint64(time.Now().UnixNano()*2)))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.IntN(len(charset))]
	}
	return string(b)
}

func String(length int) string {
	return StringWithCharset(length, charset)
}

func main() {

	var length int

	flag.IntVar(&length, "length", 256, "...")
	flag.Parse()

	fmt.Println(String(length))
}
