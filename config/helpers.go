package config

import (
	"crypto/tls"
	"crypto/x509"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func DialServers(servers map[string]*Server) (map[string]*grpc.ClientConn, error) {
	conns := make(map[string]*grpc.ClientConn)

	for _, cfg := range servers {
		if _, ok := conns[cfg.Address]; ok {
			continue
		}

		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM(cfg.Identity)
		if !ok {
			panic("Could not create cert pool for TLS connection")
		}
		creds := credentials.NewClientTLSFromCert(pool, "")

		opts := []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithWriteBufferSize(StreamSize),
			grpc.WithReadBufferSize(StreamSize),
			grpc.WithInitialWindowSize(int32(StreamSize)),
			grpc.WithInitialConnWindowSize(int32(StreamSize)),
		}

		cc, err := grpc.Dial(cfg.Address, opts...)
		if err != nil {
			return nil, err
		}

		conns[cfg.Address] = cc
	}

	return conns, nil
}

func CloseConns(conns map[string]*grpc.ClientConn) {
	for _, cc := range conns {
		cc.Close()
	}
}

func FindCertificate(addr string, servers map[string]*Server) *tls.Certificate {
	for _, server := range servers {
		if server.Address != addr {
			continue
		}
		c, err := tls.X509KeyPair(server.Identity, server.PrivateIdentity)
		if err != nil {
			panic(err)
		}
		return &c
	}
	return nil
}

func FindIdentity(addr string, servers map[string]*Server) ([]byte, []byte) {
	for _, server := range servers {
		if server.Address != addr {
			continue
		}
		return server.Identity, server.PrivateIdentity
	}
	return nil, nil
}

func GroupToKeys(servers map[string]*Server, group *Group) [][]byte {
	keys := make([][]byte, len(group.Servers))
	for i, sid := range group.Servers {
		keys[i] = servers[sid].PublicKey
	}
	return keys
}
