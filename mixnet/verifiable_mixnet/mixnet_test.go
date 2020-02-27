package verifiable_mixnet

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	mrand "math/rand"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func partOf(a []byte, arr [][]byte) bool {
	for _, b := range arr {
		if bytes.Equal(a, b) {
			return true
		}
	}
	return false
}

func TestSingleGroup(t *testing.T) {
	K := 10
	mixes := make([]Mix, K)

	publicKeys, privateKeys := make([][]byte, K), make([][]byte, K)
	for i := range publicKeys {
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		publicKeys[i] = pub[:]
		privateKeys[i] = priv[:]
	}

	for i := range mixes {
		cfg := RoundConfiguration{
			Row:     0,
			Index:   i,
			AuxSize: 0,
		}
		mix := NewMix(nil)
		mixes[i] = mix

		err := mix.NewRound(0, cfg)
		if err != nil {
			t.Error(err)
		}

		mix.SetRoundKey(0, publicKeys[i], privateKeys[i])
	}

	msgs := make([][]byte, 1000)
	ciphertexts := make([][]byte, len(msgs))
	auxs := make([][]byte, K)
	nonces := make([][]byte, K)
	for i := range nonces {
		nonce := Nonce(0, 0, i)
		nonces[i] = nonce[:]
	}

	for i := range msgs {
		msgs[i] = make([]byte, 100)
		rand.Read(msgs[i])
		keys := make([][]byte, len(publicKeys))
		copy(keys, publicKeys)

		ns := make([][]byte, len(nonces))
		copy(ns, nonces)

		ciphertexts[i] = OnionEncrypt(msgs[i], auxs, ns, keys)
	}

	res := ciphertexts
	var err error
	for i := 0; i < K; i++ {
		err = mixes[i].AddMessages(0, res)
		if err != nil {
			t.Error(err)
		}
		res, err = mixes[i].Mix(0)
		if err != nil {
			t.Error(err)
		}
	}

	if len(res) != len(msgs) {
		t.Error("Message missing")
	}

	for r := range res {
		if !partOf(res[r], msgs) {
			t.Error("Mixnet failed")
		}
	}
}

func TestSingleGroupP256(t *testing.T) {
	K := 10
	mixes := make([]Mix, K)

	publicKeys, privateKeys := make([][]byte, K), make([][]byte, K)
	for i := 0; i < K; i++ {
		pub, priv := P256KeyToBytes(GenerateP256Key())
		publicKeys[i], privateKeys[i] = pub, priv
	}

	for i := range mixes {
		cfg := RoundConfiguration{
			Row:     0,
			Index:   i,
			AuxSize: 0,
		}
		mix := NewMix(P256DecryptionWorker)
		mixes[i] = mix

		err := mix.NewRound(0, cfg)
		if err != nil {
			t.Error(err)
		}

		mix.SetRoundKey(0, publicKeys[i], privateKeys[i])
		mix.SetBlindKey(0, nil, big.NewInt(1).Bytes())
	}

	msgs := make([][]byte, 1000)
	ciphertexts := make([][]byte, len(msgs))
	auxs := make([][]byte, K)
	nonces := make([][]byte, K)
	for i := range nonces {
		nonce := Nonce(0, 0, i)
		nonces[i] = nonce[:]
	}

	for i := range msgs {
		msgs[i] = make([]byte, 100)
		rand.Read(msgs[i])
		keys := make([][]byte, len(publicKeys))
		copy(keys, publicKeys)

		ns := make([][]byte, len(nonces))
		copy(ns, nonces)

		ciphertexts[i], _ = P256OnionEncrypt(msgs[i], auxs, ns, keys, false)
	}

	res := ciphertexts
	var err error
	for i := 0; i < K; i++ {
		err = mixes[i].AddMessages(0, res)
		if err != nil {
			t.Error(err)
		}
		res, err = mixes[i].Mix(0)
		if err != nil {
			t.Error(err)
		}
	}

	if len(res) != len(msgs) {
		t.Error("Message missing")
	}

	for r := range res {
		if !partOf(res[r][64:], msgs) {
			t.Error("Mixnet failed")
		}
	}
}

func TestVerifiableSingleGroup(t *testing.T) {
	K := 10
	mixes := make([]Mix, K)

	publicKeys, privateKeys := make([][]byte, K), make([][]byte, K)
	publicBKeys, privateBKeys := make([][]byte, K), make([][]byte, K)
	basex, basey := curve.Params().Gx, curve.Params().Gy
	for i := 0; i < K; i++ {
		mx, my, mexp := GenerateP256KeyWithBase(basex, basey)
		bx, by, bexp := GenerateP256KeyWithBase(basex, basey)

		mpub, mpriv := P256KeyToBytes(mx, my, mexp)
		bpub, bpriv := P256KeyToBytes(bx, by, bexp)
		publicKeys[i], privateKeys[i] = mpub, mpriv
		publicBKeys[i], privateBKeys[i] = bpub, bpriv
		basex, basey = bx, by
	}

	for i := range mixes {
		cfg := RoundConfiguration{
			Verifiable: true,
			Row:        0,
			Index:      i,
			First:      i == 0,
			Last:       i == K-1,
			AuxSize:    0,
			GroupSize:  K,
		}
		mix := NewMix(P256DecryptionWorker)
		mixes[i] = mix

		err := mix.NewRound(0, cfg)
		if err != nil {
			t.Fatal(err)
		}

		err = mix.SetRoundKey(0, publicKeys[i], privateKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		err = mix.SetBlindKey(0, publicBKeys, privateBKeys[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	msgs := make([][]byte, 1000)
	ciphertexts := make([][]byte, len(msgs))
	clientprfs := make([][]byte, len(msgs))
	auxs := make([][]byte, K)
	nonces := make([][]byte, K)
	for i := range nonces {
		nonce := Nonce(0, 0, i)
		nonces[i] = nonce[:]
	}

	wg := new(sync.WaitGroup)
	wg.Add(len(msgs))
	for i := range msgs {
		go func(i int) {
			defer wg.Done()
			msgs[i] = make([]byte, 100)
			rand.Read(msgs[i])
			keys := make([][]byte, len(publicKeys))
			copy(keys, publicKeys)

			ns := make([][]byte, len(nonces))
			copy(ns, nonces)

			ciphertexts[i], clientprfs[i] = P256OnionEncrypt(msgs[i], auxs, ns, keys, true)
		}(i)
	}
	wg.Wait()

	for i := 0; i < K; i++ {
		err := mixes[i].AddCiphertexts(0, ciphertexts, clientprfs)
		if err != nil {
			t.Fatal(err)
		}

		if i != 0 {
			err = mixes[0].ConfirmVerification(0, true)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	for i := 0; i < K; i++ {
		err := mixes[i].StartRound(0)
		if err != nil {
			t.Fatal(err)
		}
	}

	var final [][]byte
	for i := 0; i < K; i++ {
		if i < K-1 {
			res, prf, err := mixes[i].ProveMix(0)
			if err != nil {
				t.Fatal(err)
			}

			err = mixes[i+1].AddMessages(0, res)
			if err != nil {
				t.Fatal(err)
			}

			for j := 0; j < K; j++ {
				if i == j { // no need to verify own proof
					continue
				}

				err := mixes[j].VerifyProof(0, i, res, prf)
				if err != nil {
					t.Fatal(err)
				}
				if i < K-1 {
					err = mixes[i+1].ConfirmVerification(0, true)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
		} else {
			// last server in chain
			// no need to prove
			res, err := mixes[i].Mix(0)
			if err != nil {
				t.Fatal(err)
			}
			final = res
		}
	}

	if len(final) != len(msgs) {
		t.Error("Message missing")
	}

	for r := range final {
		if !partOf(final[r][64:], msgs) {
			t.Error("Mixnet failed")
		}
	}
}

func Test2X2(t *testing.T) {
	L := 2 // number of layers
	G := 2 // number of groups / layer
	K := 3 // number of servers per group
	auxSize := 4

	// setup all mixnet
	layers := make([][][]Mix, L)
	publicKeys := make([][][][]byte, L)
	for l := range layers {
		layers[l] = make([][]Mix, G)
		publicKeys[l] = make([][][]byte, G)
		for g := range layers[l] {
			layers[l][g] = make([]Mix, K)
			publicKeys[l][g] = make([][]byte, K)
			for i := range layers[l][g] {
				cfg := RoundConfiguration{
					Row:     g,
					Index:   i,
					AuxSize: auxSize,
				}
				mix := NewMix(nil)
				layers[l][g][i] = mix

				err := mix.NewRound(0, cfg)
				if err != nil {
					t.Error(err)
				}

				pub, priv, err := box.GenerateKey(rand.Reader)
				if err != nil {
					panic(err)
				}

				publicKeys[l][g][i] = pub[:]
				err = mix.SetRoundKey(0, pub[:], priv[:])
				if err != nil {
					t.Error(err)
				}
			}
		}
	}

	msgs := make([][]byte, 4)
	ciphertexts := make([][]byte, len(msgs))
	routes := make([][]int, len(msgs))

	for i := range routes {
		routes[i] = make([]int, L)
		for r := range routes[i] {
			routes[i][r] = int(mrand.Int31n(int32(G)))
		}
	}

	for i := range msgs {
		route := routes[i]

		auxs := make([][]byte, L*K)
		pubs := make([][]byte, L*K)
		nonces := make([][]byte, L*K)

		for a := range auxs {
			auxs[a] = make([]byte, auxSize)
			binary.BigEndian.PutUint32(auxs[a], uint32(route[a/K]))
		}

		for r := range route {
			for s, key := range publicKeys[r][route[r]] {
				pubs[r*K+s] = key
				nonce := Nonce(0, route[r], s)
				nonces[r*K+s] = nonce[:]
			}
		}

		msgs[i] = make([]byte, 10)
		rand.Read(msgs[i])

		ciphertexts[i] = OnionEncrypt(msgs[i], auxs, nonces, pubs)
	}

	neighborWgs := make([][][]*sync.WaitGroup, L)
	for l := range neighborWgs {
		neighborWgs[l] = make([][]*sync.WaitGroup, G)
		for g := range neighborWgs[l] {
			neighborWgs[l][g] = make([]*sync.WaitGroup, K)
			for s := range neighborWgs[l][g] {
				neighborWgs[l][g][s] = new(sync.WaitGroup)
				if s != 0 {
					neighborWgs[l][g][s].Add(1)
				} else if s == 0 && l != 0 {
					neighborWgs[l][g][s].Add(G)
				}
			}
		}
	}

	for i := range msgs {
		route := binary.BigEndian.Uint32(ciphertexts[i][32 : 32+4])
		err := layers[0][route][0].AddMessages(0, [][]byte{ciphertexts[i]})
		if err != nil {
			t.Error(err)
		}
	}

	wg := new(sync.WaitGroup)

	for l, layer := range layers {
		for g, group := range layer {
			for s, server := range group {
				wg.Add(1)
				go func(l, g, s int, group []Mix, server Mix) {
					defer wg.Done()

					var res [][]byte
					var err error
					if !(s == K-1 && l == L-1) {
						neighborWgs[l][g][s].Wait()
						res, err = server.Mix(0)
					}
					if err != nil {
						t.Error(err)
					}

					if s == K-1 && l != L-1 {
						cs := make([][][]byte, G)
						for i := range res {
							route := binary.BigEndian.Uint32(res[i][32 : 32+4])
							cs[route] = append(cs[route], res[i])
						}
						for c := range cs {
							err = layers[l+1][c][0].AddMessages(0, cs[c])
							if err != nil {
								t.Error(err)
							}
							neighborWgs[l+1][c][0].Done()
						}
					} else if s < K-1 {
						err = group[s+1].AddMessages(0, res)
						if err != nil {
							t.Error(err)
						}
						neighborWgs[l][g][s+1].Done()
					}
				}(l, g, s, group, server)
			}
		}
	}
	wg.Wait()

	results := make(chan [][]byte, L)
	for _, group := range layers[L-1] {
		go func(server Mix) {
			res, err := server.Mix(0)
			if err != nil {
				t.Error(err)
			}
			results <- res
		}(group[K-1])
	}

	var res [][]byte
	for i := 0; i < L; i++ {
		r := <-results
		res = append(res, r...)
	}

	if len(res) != len(msgs) {
		t.Error("Message missing")
	}
	for r := range res {
		if !partOf(res[r], msgs) {
			t.Error("Message missing")
		}
	}
}

func TestAuxProcessor(t *testing.T) {
	K := 10
	mixes := make([]Mix, K)
	expectedAuxSize := 32

	auxProcessor := func(old, new []byte, auxSize int) (bool, []byte) {
		return auxSize == expectedAuxSize, nil
	}

	publicKeys := make([][]byte, K)
	for i := range mixes {
		cfg := RoundConfiguration{
			Row:     0,
			Index:   i,
			AuxSize: expectedAuxSize,
		}
		mix := NewMix(nil)
		mixes[i] = mix

		err := mix.NewRound(0, cfg)
		if err != nil {
			t.Error(err)
		}

		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}

		publicKeys[i] = pub[:]

		err = mix.SetRoundKey(0, pub[:], priv[:])
		if err != nil {
			t.Error(err)
		}

		mix.SetAuxProcessor(0, auxProcessor)
	}

	msgs := make([][]byte, 2)
	ciphertexts := make([][]byte, len(msgs))
	auxs := make([][]byte, K)
	nonces := make([][]byte, K)
	for i := range nonces {
		nonce := Nonce(0, 0, i)
		nonces[i] = nonce[:]
	}

	for i := range msgs {
		for a := range auxs {
			auxs[a] = make([]byte, expectedAuxSize)
			binary.BigEndian.PutUint32(auxs[a], 0)
		}

		msgs[i] = make([]byte, 100)
		rand.Read(msgs[i])
		keys := make([][]byte, len(publicKeys))
		copy(keys, publicKeys)

		ns := make([][]byte, len(nonces))
		copy(ns, nonces)

		ciphertexts[i] = OnionEncrypt(msgs[i], auxs, ns, keys)
	}

	res := ciphertexts
	var err error
	for i := 0; i < K; i++ {
		err = mixes[i].AddMessages(0, res)
		if err != nil {
			t.Error(err)
		}
		res, err = mixes[i].Mix(0)
		if err != nil {
			t.Error(err)
		}
	}

	if len(res) != len(msgs) {
		t.Error("Message missing")
	}

	for r := range res {
		if !partOf(res[r], msgs) {
			t.Error("Mixnet failed")
		}
	}
}
