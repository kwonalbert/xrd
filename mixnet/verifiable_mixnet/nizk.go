package verifiable_mixnet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

func PoKLog(exp, x, y *big.Int) []byte {
	prf := make([]byte, 32*3) // one elliptic curve point + one scalar

	r, _ := rand.Int(rand.Reader, order)
	rx, ry := curve.ScalarBaseMult(r.Bytes())
	rxb := rx.Bytes()
	ryb := ry.Bytes()
	copy(prf[32-len(rxb):], rxb)
	copy(prf[64-len(ryb):], ryb)

	buf := new(bytes.Buffer)
	buf.Write(x.Bytes())
	buf.Write(y.Bytes())
	buf.Write(prf[:64])

	c := sha256.Sum256(buf.Bytes())
	C := new(big.Int).SetBytes(c[:])

	C.Mul(C, exp)
	C.Sub(r, C)
	C.Mod(C, order)

	Cb := C.Bytes() // this is r - c*exp
	copy(prf[96-len(Cb):], Cb)

	return prf
}

func VerifyPoKLog(x, y *big.Int, prf []byte) bool {
	rx := new(big.Int).SetBytes(prf[:32])
	ry := new(big.Int).SetBytes(prf[32:64])

	buf := new(bytes.Buffer)
	buf.Write(x.Bytes())
	buf.Write(y.Bytes())
	buf.Write(prf[:64])

	c := sha256.Sum256(buf.Bytes())

	nx, ny := curve.ScalarBaseMult(prf[64:])
	cx, cy := curve.ScalarMult(x, y, c[:])

	resx, resy := curve.Add(nx, ny, cx, cy)
	return resx.Cmp(rx) == 0 && resy.Cmp(ry) == 0
}

func LogEquivalence(exp, basex1, basey1, x1, y1, basex2, basey2, x2, y2 *big.Int) []byte {
	prf := make([]byte, 32*5) // two elliptic curve points + one scalar
	r, _ := rand.Int(rand.Reader, order)

	rx1, ry1 := curve.ScalarMult(basex1, basey1, r.Bytes())
	rx2, ry2 := curve.ScalarMult(basex2, basey2, r.Bytes())
	rx1b, ry1b := rx1.Bytes(), ry1.Bytes()
	rx2b, ry2b := rx2.Bytes(), ry2.Bytes()
	copy(prf[32-len(rx1b):], rx1b)
	copy(prf[64-len(ry1b):], ry1b)
	copy(prf[96-len(rx2b):], rx2b)
	copy(prf[128-len(ry2b):], ry2b)

	buf := new(bytes.Buffer)
	buf.Write(basex1.Bytes())
	buf.Write(basey1.Bytes())
	buf.Write(x1.Bytes())
	buf.Write(y1.Bytes())
	buf.Write(basex2.Bytes())
	buf.Write(basey2.Bytes())
	buf.Write(x2.Bytes())
	buf.Write(y2.Bytes())
	buf.Write(prf[:128])

	c := sha256.Sum256(buf.Bytes())

	C := new(big.Int).SetBytes(c[:])

	C.Mul(C, exp)
	C.Sub(r, C)
	C.Mod(C, order)

	Cb := C.Bytes() // this is r - c*exp
	copy(prf[160-len(Cb):], Cb)
	return prf
}

func VerifyLogEquivalence(basex1, basey1, x1, y1, basex2, basey2, x2, y2 *big.Int, prf []byte) bool {
	rx1 := new(big.Int).SetBytes(prf[:32])
	ry1 := new(big.Int).SetBytes(prf[32:64])
	rx2 := new(big.Int).SetBytes(prf[64:96])
	ry2 := new(big.Int).SetBytes(prf[96:128])

	buf := new(bytes.Buffer)
	buf.Write(basex1.Bytes())
	buf.Write(basey1.Bytes())
	buf.Write(x1.Bytes())
	buf.Write(y1.Bytes())
	buf.Write(basex2.Bytes())
	buf.Write(basey2.Bytes())
	buf.Write(x2.Bytes())
	buf.Write(y2.Bytes())
	buf.Write(prf[:128])

	c := sha256.Sum256(buf.Bytes())

	nx1, ny1 := curve.ScalarMult(basex1, basey1, prf[128:])
	nx2, ny2 := curve.ScalarMult(basex2, basey2, prf[128:])

	cx1, cy1 := curve.ScalarMult(x1, y1, c[:])
	cx2, cy2 := curve.ScalarMult(x2, y2, c[:])

	resx1, resy1 := curve.Add(nx1, ny1, cx1, cy1)
	resx2, resy2 := curve.Add(nx2, ny2, cx2, cy2)
	return resx1.Cmp(rx1) == 0 && resy1.Cmp(ry1) == 0 && resx2.Cmp(rx2) == 0 && resy2.Cmp(ry2) == 0
}
