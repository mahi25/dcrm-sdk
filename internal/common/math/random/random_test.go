package random

import (
	"testing"
)

func TestGetRandomInt(t *testing.T) {
	rndInt := GetRandomInt(1024)
	t.Log(rndInt)
}

func TestGetRandomIntFromZn(t *testing.T) {
	rndInt := GetRandomInt(1024)
	t.Log(rndInt)
	rndIntZn := GetRandomIntFromZn(rndInt)
	t.Log(rndIntZn)
}

func TestGetRandomIntFromZnStar(t *testing.T) {
	rndInt := GetRandomInt(1024)
	t.Log(rndInt)
	rndIntZnStar := GetRandomIntFromZnStar(rndInt)
	t.Log(rndIntZnStar)
}

func TestGetRandomPrimeInt(t *testing.T) {
	primeInt := GetRandomPrimeInt(1024)
	t.Log(primeInt)
}
