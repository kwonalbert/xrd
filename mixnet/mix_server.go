package mixnet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/big"
	"strconv"
	"sync"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/span"
	"github.com/kwonalbert/xrd/mixnet/verifiable_mixnet"
)

type point struct {
	x *big.Int
	y *big.Int
}

type server struct {
	coordinator ecdsa.PublicKey

	// all maps are only used for concurrent reads so no need to mutex
	servers map[string]*config.Server
	groups  map[string]*config.Group
	partOf  map[string]*config.Group

	configs   map[string]verifiable_mixnet.RoundConfiguration
	mixes     map[string]verifiable_mixnet.Mix
	verifiers map[string]Verifier
	conns     map[string]*grpc.ClientConn
	groupRpcs map[string][]MixClient

	mixLock sync.Mutex

	slock  sync.Mutex
	states map[string]map[int]*roundState
}

type roundState struct {
	sync.RWMutex
	msgs      [][]byte
	msgwg     *sync.WaitGroup
	shuffleWg *sync.WaitGroup
}

func NewMixServer(addr string, coordinator ecdsa.PublicKey, servers map[string]*config.Server, groups map[string]*config.Group) MixServer {
	mixes := make(map[string]verifiable_mixnet.Mix)
	verifiers := make(map[string]Verifier)
	for _, server := range servers {
		if server.Address != addr {
			continue
		}
		mix := verifiable_mixnet.NewMix(verifiable_mixnet.P256DecryptionWorker)
		mixes[server.Id] = mix
	}

	partOf := make(map[string]*config.Group)
	configs := make(map[string]verifiable_mixnet.RoundConfiguration)
	for _, group := range groups {
		for s, sid := range group.Servers {
			verifiers[sid] = NewVerifier(s, len(group.Servers))

			if servers[sid].Address != addr {
				continue
			}

			cfg := verifiable_mixnet.RoundConfiguration{
				ClientVerifiable: false, // for experiments, turn this off
				Verifiable:       true,
				Row:              int(group.Row),
				Layer:            0,
				Index:            s,
				First:            s == 0,
				Last:             s == len(group.Servers)-1,
				AuxSize:          0,
				GroupSize:        len(group.Servers),
			}
			configs[sid] = cfg
			partOf[sid] = group
		}
	}

	s := &server{
		coordinator: coordinator,

		servers: servers,
		groups:  groups,
		partOf:  partOf,

		configs:   configs,
		mixes:     mixes,
		verifiers: verifiers,

		states: make(map[string]map[int]*roundState),
	}
	return s
}

// only coordinator is allowed to call NewRound, EndRound, and Mix on the first server
// TODO: Add authentication for all functions

func (srv *server) dialOnce() error {
	if srv.conns != nil {
		return nil
	}

	conns := make(map[string]*grpc.ClientConn)
	groupRpcs := make(map[string][]MixClient)

	for sid, group := range srv.partOf {
		rpcs := make([]MixClient, len(group.Servers))
		for i, id := range group.Servers {
			server := srv.servers[id]
			if _, ok := conns[server.Address]; !ok {
				pool := x509.NewCertPool()
				ok := pool.AppendCertsFromPEM(server.Identity)
				if !ok {
					panic("Could not create cert pool for TLS connection")
				}
				creds := credentials.NewClientTLSFromCert(pool, "")

				opts := []grpc.DialOption{
					grpc.WithTransportCredentials(creds),
				}

				cc, err := grpc.Dial(server.Address, opts...)
				if err != nil {
					return err
				}
				conns[server.Address] = cc
			}
			rpcs[i] = NewMixClient(conns[server.Address])
		}
		groupRpcs[sid] = rpcs
	}

	srv.conns = conns
	srv.groupRpcs = groupRpcs
	return nil
}

func (srv *server) NewRound(ctx context.Context, in *NewRoundRequest) (*NewRoundResponse, error) {
	if err := srv.dialOnce(); err != nil {
		return nil, err
	}

	round := int(in.Round)
	srv.slock.Lock()

	blindkey := make([]byte, 64)
	curve := elliptic.P256()
	gxb, gyb := curve.Params().Gx.Bytes(), curve.Params().Gy.Bytes()
	copy(blindkey[32-len(gxb):], gxb)
	copy(blindkey[64-len(gyb):], gyb)

	for sid, mix := range srv.mixes {
		verifier := srv.verifiers[sid]
		cfg := srv.configs[sid]

		err := verifier.NewRound(int(in.Round))
		if err != nil {
			return nil, err
		}

		err = mix.NewRound(round, cfg)
		if err != nil {
			return nil, err
		}
		server := srv.servers[sid]
		err = mix.SetRoundKey(round, server.PublicKey, server.PrivateKey)
		if err != nil {
			return nil, err
		}

		publicBlindKeys := make([][]byte, len(srv.partOf[sid].Servers))
		for p := range publicBlindKeys {
			publicBlindKeys[p] = blindkey
		}

		// TODO: change to the actual blind key
		err = mix.SetBlindKey(round, publicBlindKeys, []byte{1})
		if err != nil {
			return nil, err
		}

		groupSize := len(srv.partOf[sid].Servers)
		wg := new(sync.WaitGroup)
		wg.Add(1)
		if _, ok := srv.states[sid]; !ok {
			srv.states[sid] = make(map[int]*roundState)
		}

		swg := new(sync.WaitGroup)
		// the last server doesn't submit proofs
		// and no need to take the current one into consideration
		if cfg.Last {
			swg.Add(groupSize - 1)
		} else {
			swg.Add(groupSize - 2)
		}
		state := &roundState{
			msgs:      nil,
			msgwg:     wg,
			shuffleWg: swg,
		}

		srv.states[sid][round] = state
	}
	srv.slock.Unlock()

	return &NewRoundResponse{}, nil
}

func (srv *server) EndRound(ctx context.Context, in *EndRoundRequest) (*EndRoundResponse, error) {
	round := int(in.Round)
	for id := range srv.states {
		delete(srv.states[id], round)
	}

	for _, mix := range srv.mixes {
		err := mix.EndRound(round)
		if err != nil {
			return nil, err
		}
	}

	return &EndRoundResponse{}, nil
}

func (srv *server) AddMessages(stream Mix_AddMessagesServer) error {
	ctx := stream.Context()
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("Missing id in context")
	}
	id := md["id"][0]
	mix, ok := srv.mixes[id]
	if !ok {
		return errors.New("Invalid mix id")
	}
	round, err := strconv.Atoi(md["round"][0])
	if err != nil {
		return err
	}

	// TODO: see if this really helps..
	// if the upstream is a server, then process all of this
	// server's messages first before accepting other jobs
	source := md["source"][0]
	if source == Source_SERVER.String() {
		srv.mixLock.Lock()
		defer srv.mixLock.Unlock()
	}

	errs := make(chan error, 10)
	cnt := 0
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			err := stream.SendAndClose(&AddMessagesResponse{})
			if err != nil {
				return err
			}
			break
		} else if err != nil {
			return err
		}

		go func(round int, msgs [][]byte) {
			err := mix.AddMessages(round, msgs)
			errs <- err
		}(round, req.Messages)
		cnt++
	}

	for i := 0; i < cnt; i++ {
		err := <-errs
		if err != nil {
			return err
		}
	}

	srv.shuffleAndSend(round, id, mix)

	return nil
}

func (srv *server) shuffleAndSend(round int, id string, mix verifiable_mixnet.Mix) {
	cfg, err := mix.RoundConfiguration(round)
	if err != nil {
		log.Println("shuffle:", err)
	}

	// if cfg.Row == 0 {
	// 	log.Println(cfg.Index, "receiving took:", time.Since(start))
	// 	log.Println(cfg.Index, "stream cnt:", cnt)
	// }

	// the first server needs to wait for Mix call
	// otherwise, shuffle
	if !cfg.First {
		if cfg.Last { // only need to store the shuffled value if last server
			shuffled, err := mix.Mix(round)
			if err != nil {
				log.Println("Mix error:", err)
			}

			state := srv.states[id][round]

			for m := range shuffled {
				shuffled[m] = shuffled[m][verifiable_mixnet.POINT_SIZE:]
			}

			state.Lock()
			state.msgs = shuffled
			state.msgwg.Done()
			state.Unlock()
		} else {
			shuffled, prf, err := mix.ProveMix(round)
			if err != nil {
				log.Println("Mix error:", err)
			}

			go srv.sendMessages(round, id, shuffled)
			go srv.sendBlindProofs(round, id, shuffled, prf)
		}
		if cfg.Row == 0 {
			log.Println(cfg.Index, "mixed")
		}
	}

}

func (srv *server) sendBlindProofs(round int, id string, shuffled [][]byte, prf []byte) error {
	idx := -1
	for i, sid := range srv.partOf[id].Servers {
		if sid == id {
			idx = i
		}
	}
	roundStr := strconv.Itoa(round)
	idxStr := strconv.Itoa(idx)

	// send blind proofs
	keys := make([][]byte, len(shuffled))
	for c, text := range shuffled {
		keys[c] = text[:verifiable_mixnet.POINT_SIZE]
	}

	kspans := span.StreamSpan(len(keys), config.StreamSize-len(prf), len(keys[0]))

	errs := make(chan error, len(srv.groupRpcs[id]))
	for i, rpc := range srv.groupRpcs[id] {
		go func(i int, rpc MixClient) {
			if i == idx {
				return
			}

			md := metadata.Pairs(
				"id", srv.partOf[id].Servers[i],
				"round", roundStr,
				"index", idxStr,
			)
			ctx := metadata.NewOutgoingContext(context.Background(), md)

			stream, err := rpc.VerifyProof(ctx)
			if err != nil {
				errs <- err
			}

			for s, span := range kspans {
				req := &VerifyProofRequest{
					Round: uint64(round),
					Index: uint32(idx),
					Keys:  keys[span.Start:span.End],
				}

				if s == 0 {
					req.Proof = prf
				}
				err := stream.Send(req)
				if err != nil {
					errs <- err
				}
			}
			_, err = stream.CloseAndRecv()
			errs <- err

		}(i, rpc)
	}

	for i := range srv.groupRpcs[id] {
		if i == idx {
			continue
		}

		err := <-errs
		if err != nil && err != io.EOF {
			log.Println("Send failed:", err)
			return err
		}
	}
	return nil
}

func (srv *server) sendMessages(round int, id string, shuffled [][]byte) error {
	neighborIdx := -1
	for i, sid := range srv.partOf[id].Servers {
		if sid == id {
			neighborIdx = i + 1
		}
	}
	roundStr := strconv.Itoa(round)

	// actually send messages
	md := metadata.Pairs(
		"id", srv.partOf[id].Servers[neighborIdx],
		"round", roundStr,
		"source", Source_SERVER.String(),
	)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	spans := span.StreamSpan(len(shuffled), config.StreamSize, len(shuffled[0]))

	stream, err := srv.groupRpcs[id][neighborIdx].AddMessages(ctx)
	if err != nil {
		return err
	}

	for _, span := range spans {
		req := &AddMessagesRequest{
			Round:    uint64(round),
			Messages: shuffled[span.Start:span.End],
		}

		err = stream.Send(req)
		if err != nil {
			log.Println("Server failed to stream messages:", err)
		}
	}

	_, err = stream.CloseAndRecv()
	if err != nil && err != io.EOF {
		return err
	}

	return nil
}

func (srv *server) GetMessages(ctx context.Context, in *GetMessagesRequest) (*GetMessagesResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("Missing id in context")
	}
	id := md["id"][0]
	mix, ok := srv.mixes[id]
	if !ok {
		return nil, errors.New("Invalid mix id")
	}
	cfg, err := mix.RoundConfiguration(int(in.Round))
	if err != nil {
		return nil, err
	}
	if !cfg.Last {
		return nil, errors.New("Cannot get message from a non-last mix")
	}

	state, ok := srv.states[id][int(in.Round)]
	if !ok {
		return nil, errors.New("Round not yet processed")
	}
	state.msgwg.Wait()

	state.Lock()
	defer state.Unlock()

	return &GetMessagesResponse{
		Messages: state.msgs,
	}, nil
}

func (srv *server) submitVerified(round int, id string, index int, verified bool) error {
	// send whether the user nizks verified
	vmd := metadata.Pairs(
		"id", srv.partOf[id].Servers[index],
		"source", Source_SERVER.String(),
	)
	vctx := metadata.NewOutgoingContext(context.Background(), vmd)

	verReq := &ConfirmVerificationRequest{
		Round:    uint64(round),
		Verified: verified,
	}
	_, err := srv.groupRpcs[id][index].ConfirmVerification(vctx, verReq)
	return err
}

func (srv *server) StartRound(ctx context.Context, in *StartRoundRequest) (*StartRoundResponse, error) {
	round := int(in.Round)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("Missing id in context")
	}
	id := md["id"][0]
	mix, ok := srv.mixes[id]
	if !ok {
		return nil, errors.New("Invalid mix id")
	}
	cfg, err := mix.RoundConfiguration(round)
	if err != nil {
		return nil, err
	}

	err = mix.StartRound(round)
	if err != nil {
		return nil, err
	}

	if cfg.First {
		shuffled, prf, err := mix.ProveMix(round)
		if err != nil {
			return nil, err
		}

		go srv.sendMessages(round, id, shuffled)
		go srv.sendBlindProofs(round, id, shuffled, prf)
	} else {
		err := srv.submitVerified(round, id, 0, true)
		if err != nil {
			return nil, err
		}
	}
	return &StartRoundResponse{}, nil
}

func (srv *server) SubmitCiphertexts(stream Mix_SubmitCiphertextsServer) error {
	ctx := stream.Context()
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("Missing id in context")
	}
	id := md["id"][0]
	mix, ok := srv.mixes[id]
	if !ok {
		return errors.New("Invalid mix id")
	}

	round, err := strconv.Atoi(md["round"][0])
	if err != nil {
		return err
	}

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		err = mix.AddCiphertexts(round, req.Ciphertexts, req.Proofs)
		if err != nil {
			return err
		}
	}

	err = stream.SendAndClose(&SubmitCiphertextsResponse{})
	if err != nil {
		return err
	}

	return nil
}

func (srv *server) VerifyProof(stream Mix_VerifyProofServer) error {
	ctx := stream.Context()
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("Missing id in context")
	}
	id := md["id"][0]
	mix, ok := srv.mixes[id]
	if !ok {
		return errors.New("Invalid mix id")
	}

	round, err := strconv.Atoi(md["round"][0])
	if err != nil {
		return err
	}

	index, err := strconv.Atoi(md["index"][0])
	if err != nil {
		return err
	}

	var keys [][]byte
	var prf []byte

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		keys = append(keys, req.Keys...)

		if req.Proof != nil && prf == nil {
			prf = req.Proof
		}
	}

	err = mix.VerifyProof(round, index, keys, prf)
	if err != nil {
		return err
	}

	state := srv.states[id][round]
	state.shuffleWg.Done()

	if index < len(srv.groupRpcs[id])-1 {
		err = srv.submitVerified(round, id, index+1, true)
		return err
	} else {
		return nil
	}
}

func (srv *server) ConfirmVerification(ctx context.Context, in *ConfirmVerificationRequest) (*ConfirmVerificationResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("Missing id in context")
	}
	id := md["id"][0]
	mix, ok := srv.mixes[id]
	if !ok {
		return nil, errors.New("Invalid mix id")
	}

	return &ConfirmVerificationResponse{}, mix.ConfirmVerification(int(in.Round), in.Verified)
}

func (srv *server) GetInnerKey(ctx context.Context, in *GetInnerKeyRequest) (*GetInnerKeyResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("Missing id in context")
	}
	id := md["id"][0]

	x, y, err := srv.verifiers[id].PublicKey(int(in.Round))
	if err != nil {
		return nil, err
	}

	return &GetInnerKeyResponse{
		X: x.Bytes(),
		Y: y.Bytes(),
	}, nil
}

func (srv *server) AddInnerCiphertexts(ctx context.Context, in *AddInnerCiphertextsRequest) (*AddInnerCiphertextsResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("Missing id in context")
	}
	id := md["id"][0]

	err := srv.verifiers[id].AddInnerCiphertexts(int(in.Round), in.Messages)
	if err != nil {
		return nil, err
	}

	return &AddInnerCiphertextsResponse{}, nil
}

func (srv *server) GetPrivateInnerKey(ctx context.Context, in *GetPrivateInnerKeyRequest) (*GetPrivateInnerKeyResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("Missing id in context")
	}
	id := md["id"][0]

	verifier, ok := srv.verifiers[id]
	if !ok {
		return nil, errors.New("Id not found")
	}

	round := int(in.Round)
	state := srv.states[id][round]
	state.shuffleWg.Wait()

	// wait for all servers to shuffle, and return
	priv, err := verifier.PrivateKey(round)
	if err != nil {
		return nil, err
	}
	return &GetPrivateInnerKeyResponse{
		PrivateKey: priv.Bytes(),
	}, nil
}

func (srv *server) Finalize(ctx context.Context, in *FinalizeRequest) (*FinalizeResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("Missing id in context")
	}
	id := md["id"][0]

	verifier, ok := srv.verifiers[id]
	if !ok {
		return nil, errors.New("Id not found")
	}
	round := int(in.Round)

	req := &GetPrivateInnerKeyRequest{
		Round: in.Round,
	}

	group := srv.partOf[id]
	privateKeys := make([][]byte, len(group.Servers))
	errs := make(chan error, len(group.Servers))
	for i, sid := range group.Servers {
		go func(i int, sid string) {
			md := metadata.Pairs(
				"id", sid,
			)
			ctx := metadata.NewOutgoingContext(context.Background(), md)
			resp, err := srv.groupRpcs[id][i].GetPrivateInnerKey(ctx, req)
			if err == nil {
				privateKeys[i] = resp.PrivateKey
			}
			errs <- err
		}(i, sid)
	}
	for i := 0; i < len(group.Servers); i++ {
		err := <-errs
		if err != nil {
			return nil, err
		}
	}

	plaintexts, err := verifier.Finalize(round, privateKeys)

	return &FinalizeResponse{
		Plaintexts: plaintexts,
	}, err
}
