package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/kwonalbert/xrd/mixnet/verifiable_mixnet"
)

func Port(addr string) string {
	return ":" + strings.Split(addr, ":")[1]
}

func SelfSignedCertificate(name pkix.Name) ([]byte, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// if old certificate is not valid any more
	// or first time registering, generate a new cert
	serial, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		panic(err)
	}

	now := time.Now()
	expiration := time.Now().Add(8760 * time.Hour) // year from now

	template := &x509.Certificate{
		SerialNumber: serial,
		Issuer:       name,
		Subject:      name,

		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          priv.PublicKey,

		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign,

		NotBefore: now.Add(-10 * time.Minute).UTC(),
		NotAfter:  expiration.UTC(),
	}

	if ip := net.ParseIP(name.CommonName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	return der, priv
}

func CreateServer(addr string, id string) *Server {
	ip := addr
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}

	name := pkix.Name{
		CommonName:   ip,
		Organization: []string{"MIT"},
		Country:      []string{"US"},
	}

	certDer, certPriv := SelfSignedCertificate(name)
	keyDer, err := x509.MarshalECPrivateKey(certPriv)
	if err != nil {
		panic(err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})

	return CreateServerWithCertificate(addr, id, certPem, keyPem)
}

func CreateServerWithExisting(addr string, id string, servers map[string]*Server) *Server {
	cert, key := FindIdentity(addr, servers)
	if cert != nil {
		return CreateServerWithCertificate(addr, id, cert, key)
	} else {
		return CreateServer(addr, id)
	}
}

func CreateServerWithCertificate(addr string, id string, cert, key []byte) *Server {
	x, y, p := verifiable_mixnet.GenerateP256Key()
	pub, priv := make([]byte, 64), make([]byte, 32)
	xb, yb, pb := x.Bytes(), y.Bytes(), p.Bytes()

	copy(pub[32-len(xb):], xb)
	copy(pub[64-len(yb):], yb)
	copy(priv[32-len(pb):], pb)

	s := &Server{
		Address:         addr,
		Id:              id,
		Identity:        cert,
		PrivateIdentity: key,
		PublicKey:       pub,
		PrivateKey:      priv,
		Extensions:      nil,
	}
	return s
}
