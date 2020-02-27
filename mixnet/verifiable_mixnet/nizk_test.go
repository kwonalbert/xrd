package verifiable_mixnet

import (
	"crypto/rand"
	"log"
	"testing"
)

func TestPoKLog(t *testing.T) {
	for i := 0; i < 100; i++ {
		privateKey, err := rand.Int(rand.Reader, curve.Params().N)
		if err != nil {
			panic(err)
		}
		publicX, publicY := curve.ScalarBaseMult(privateKey.Bytes())

		prf := PoKLog(privateKey, publicX, publicY)
		if !VerifyPoKLog(publicX, publicY, prf) {
			log.Println("trial", i)
			t.Fatal("Discrete log failed")
		}
	}
}

func TestLogEquivalence(t *testing.T) {
	for i := 0; i < 100; i++ {
		exp, err := rand.Int(rand.Reader, curve.Params().N)
		if err != nil {
			panic(err)
		}

		bexp1, err := rand.Int(rand.Reader, curve.Params().N)
		if err != nil {
			panic(err)
		}
		bexp2, err := rand.Int(rand.Reader, curve.Params().N)
		if err != nil {
			panic(err)
		}
		basex1, basey1 := curve.ScalarBaseMult(bexp1.Bytes())
		basex2, basey2 := curve.ScalarBaseMult(bexp2.Bytes())

		x1, y1 := curve.ScalarMult(basex1, basey1, exp.Bytes())
		x2, y2 := curve.ScalarMult(basex2, basey2, exp.Bytes())

		prf := LogEquivalence(exp, basex1, basey1, x1, y1, basex2, basey2, x2, y2)
		if !VerifyLogEquivalence(basex1, basey1, x1, y1,
			basex2, basey2, x2, y2, prf) {
			log.Println("trial", i)
			t.Fatal("Log equivalence failed")
		}
	}
}

func BenchmarkProvePoKLog(b *testing.B) {
	privateKey, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	publicX, publicY := curve.ScalarBaseMult(privateKey.Bytes())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PoKLog(privateKey, publicX, publicY)
	}
}

func BenchmarkVerifyPoKLog(b *testing.B) {
	privateKey, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	publicX, publicY := curve.ScalarBaseMult(privateKey.Bytes())

	prf := PoKLog(privateKey, publicX, publicY)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyPoKLog(publicX, publicY, prf)
	}
}

func BenchmarkProveLogEquivalence(b *testing.B) {
	exp, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}

	bexp1, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	bexp2, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	basex1, basey1 := curve.ScalarBaseMult(bexp1.Bytes())
	basex2, basey2 := curve.ScalarBaseMult(bexp2.Bytes())

	x1, y1 := curve.ScalarMult(basex1, basey1, exp.Bytes())
	x2, y2 := curve.ScalarMult(basex2, basey2, exp.Bytes())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LogEquivalence(exp, basex1, basey1, x1, y1, basex2, basey2, x2, y2)
	}
}

func BenchmarkVerifyLogEquivalence(b *testing.B) {
	exp, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}

	bexp1, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	bexp2, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}
	basex1, basey1 := curve.ScalarBaseMult(bexp1.Bytes())
	basex2, basey2 := curve.ScalarBaseMult(bexp2.Bytes())

	x1, y1 := curve.ScalarMult(basex1, basey1, exp.Bytes())
	x2, y2 := curve.ScalarMult(basex2, basey2, exp.Bytes())

	prf := LogEquivalence(exp, basex1, basey1, x1, y1, basex2, basey2, x2, y2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyLogEquivalence(basex1, basey1, x1, y1,
			basex2, basey2, x2, y2, prf)
	}
}

func BenchmarkAdd(b *testing.B) {
	r1, _ := rand.Int(rand.Reader, curve.Params().N)
	r2, _ := rand.Int(rand.Reader, curve.Params().N)

	x1, y1 := curve.ScalarBaseMult(r1.Bytes())
	x2, y2 := curve.ScalarBaseMult(r2.Bytes())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		curve.Add(x1, y1, x2, y2)
	}
}

func BenchmarkMul(b *testing.B) {
	r1, _ := rand.Int(rand.Reader, curve.Params().N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		curve.ScalarBaseMult(r1.Bytes())
	}
}
