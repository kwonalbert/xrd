package client

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math"
	"math/big"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"

	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/mailbox"
	"github.com/kwonalbert/xrd/mixnet"
	"github.com/kwonalbert/xrd/mixnet/verifiable_mixnet"	
	"github.com/kwonalbert/xrd/span"
)

type client struct {
	n int

	publicKeys  []*[32]byte
	privateKeys []*[32]byte

	assignments map[[32]byte][]*config.Group
	maxLoad     int

	mailboxes map[string]*config.Server
	servers   map[string]*config.Server
	groups    map[string]*config.Group

	ciphertexts map[string][][]byte
	prfs        map[string][][]byte
}

// n: number of virtual clients this will handle
func NewClient(mailboxes, servers map[string]*config.Server, groups map[string]*config.Group) ClientServer {
	c := &client{
		mailboxes: mailboxes,
		servers:   servers,
		groups:    groups,
	}
	return c
}

func (clt *client) setupRound(round int, n int) {
	pubs, privs := make([]*[32]byte, n), make([]*[32]byte, n)
	var err error
	for i := range pubs {
		pubs[i], privs[i], err = box.GenerateKey(rand.Reader)
		if err != nil {
			panic("Could not generate private keys")
		}
	}

	tmpAssign := config.Assignments(clt.groups)
	assignments := make(map[[32]byte][]*config.Group)

	// find the assignement group ids per user
	// spans := span.NSpans(n, len(tmpAssign))
	// for i, span := range spans {
	// 	for _, pub := range pubs[span.Start:span.End] {
	// 		assignments[string((*pub)[:])] = tmpAssign[i]
	// 	}
	// }

	division, maxLoad := findOptimalAssignment(clt.groups, tmpAssign)

	end := 0
	for a := range tmpAssign {
		start := end
		offset := int(math.Ceil(division[a] * float64(n)))
		end = start + offset
		if start+offset > n || a == len(tmpAssign)-1 {
			end = n
		}
		for _, pub := range pubs[start:end] {
			assignments[(*pub)] = tmpAssign[a]
		}
	}

	counts := make(map[string]int)
	for gid := range clt.groups {
		counts[gid] = 0
	}

	for _, v := range assignments {
		for _, group := range v {
			counts[group.Gid]++
		}
	}

	// for gid := range clt.groups {
	// 	if counts[gid] == 0 {
	// 		log.Println(gid, "empty")
	// 	}
	// }

	clt.publicKeys = pubs
	clt.privateKeys = privs
	clt.assignments = assignments
	clt.maxLoad = int(maxLoad*float64(n)) + 1
}

func (clt *client) mapUsers() map[[32]byte]string {
	mailboxMap := make(map[[32]byte]string)
	spans := span.NSpans(clt.n, len(clt.mailboxes))

	mlist := make([]string, len(clt.mailboxes))
	i := 0
	for k := range clt.mailboxes {
		mlist[i] = k
		i++
	}
	sort.Strings(mlist)

	i = 0
	for _, k := range mlist {
		for _, pub := range clt.publicKeys[spans[i].Start:spans[i].End] {
			mailboxMap[*pub] = k
		}
		i++
	}
	return mailboxMap
}

type clientJob struct {
	publicKey *[32]byte
	msg       []byte
	results   chan clientResult
}

type clientResult struct {
	key         *[32]byte
	ciphertexts [][]byte
	prfs        [][]byte
}

func clientWorker(round int, servers map[string]*config.Server, groups map[string]*config.Group, xs, ys map[string][]*big.Int, assignments map[[32]byte][]*config.Group, groupSize int, jobs chan clientJob) {
	var nonce [24]byte
	binary.PutUvarint(nonce[:], uint64(round))

	nonces := make([][]byte, groupSize)
	auxs := make([][]byte, groupSize)

	envClients := make(map[string]mixnet.Client)
	for gid := range groups {
		envClients[gid] = mixnet.NewClient()
		envClients[gid].NewRound(round, xs[gid], ys[gid])
	}

	_, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic("Could not generate key for encryption")
	}

	for job := range jobs {
		myGroups := assignments[*job.publicKey]
		mails := make([]*mailbox.Mail, len(myGroups))
		ciphertexts := make([][]byte, len(myGroups))
		prfs := make([][]byte, len(myGroups))
		for g := range myGroups {
			mails[g] = mailbox.SealMail(job.publicKey, priv, &nonce, job.msg)
		}

		for g, group := range myGroups {
			for i := range nonces {
				nonce := verifiable_mixnet.Nonce(round, int(group.Row), i)
				nonces[i] = nonce[:]
			}
			onionKeys := config.GroupToKeys(servers, group)
			mb := mailbox.MarshalMail(mails[g])

			inner := envClients[group.Gid].GenerateRoundInput(round, mb)
			ciphertexts[g], prfs[g] = verifiable_mixnet.P256OnionEncrypt(inner, auxs, nonces, onionKeys, true)
		}
		job.results <- clientResult{
			key:         job.publicKey,
			ciphertexts: ciphertexts,
			prfs:        prfs,
		}
	}
}

func (clt *client) getInnerKeys(round int) (map[string][]*big.Int, map[string][]*big.Int, error) {
	xm := make(map[string][]*big.Int)
	ym := make(map[string][]*big.Int)

	conns, err := config.DialServers(clt.servers)
	if err != nil {
		return nil, nil, err
	}
	defer config.CloseConns(conns)

	for gid, cfg := range clt.groups {
		xs := make([]*big.Int, len(cfg.Servers))
		ys := make([]*big.Int, len(xs))
		for i, sid := range cfg.Servers {
			rpc := mixnet.NewMixClient(conns[clt.servers[sid].Address])
			md := metadata.Pairs(
				"id", sid,
			)
			ctx := metadata.NewOutgoingContext(context.Background(), md)
			resp, err := rpc.GetInnerKey(ctx, &mixnet.GetInnerKeyRequest{
				Round: uint64(round),
			})
			if err != nil {
				log.Println("Could not fetch inner keys from servers")
				return nil, nil, err
			}
			xs[i], ys[i] = new(big.Int).SetBytes(resp.X), new(big.Int).SetBytes(resp.Y)
		}
		xm[gid] = xs
		ym[gid] = ys
	}

	return xm, ym, nil
}

func (clt *client) generateExperimentMessages(round, msgSize int) (map[string][][]byte, map[string][][]byte, error) {
	xs, ys, err := clt.getInnerKeys(round)
	if err != nil {
		return nil, nil, err
	}

	groupSize := -1
	for _, group := range clt.groups {
		groupSize = len(group.Servers)
		break
	}

	jobs := make(chan clientJob, runtime.NumCPU()*2)
	for i := 0; i < runtime.NumCPU()*2; i++ {
		go clientWorker(round, clt.servers, clt.groups, xs, ys, clt.assignments, groupSize, jobs)
	}
	results := make(chan clientResult, runtime.NumCPU()*2)

	msg := make([]byte, msgSize)
	for _, pub := range clt.publicKeys {
		go func(pub *[32]byte) {
			jobs <- clientJob{
				publicKey: pub,
				msg:       msg,
				results:   results,
			}
		}(pub)
	}

	// create per chain requests
	ciphertexts := make(map[string][][]byte)
	prfs := make(map[string][][]byte)

	for range clt.publicKeys {
		res := <-results
		for c, ciphertext := range res.ciphertexts {
			group := clt.assignments[*res.key][c]
			ciphertexts[group.Gid] = append(ciphertexts[group.Gid], ciphertext)
			prfs[group.Gid] = append(prfs[group.Gid], res.prfs[c])
		}
	}

	close(jobs)
	close(results)

	return ciphertexts, prfs, nil
}

func (clt *client) RegisterUsers(ctx context.Context, in *RegisterUsersRequest) (*RegisterUsersResponse, error) {
	clt.n = int(in.NumUsers) // keep this value around to reuse later

	// first create users
	clt.setupRound(int(in.Round), int(in.NumUsers))

	mailboxMap := clt.mapUsers()

	conns, err := config.DialServers(clt.mailboxes)
	if err != nil {
		return nil, err
	}
	defer config.CloseConns(conns)

	rpcs := make(map[string]mailbox.MailboxClient)
	for mid, cfg := range clt.mailboxes {
		rpcs[mid] = mailbox.NewMailboxClient(conns[cfg.Address])
	}

	spans := span.NSpans(clt.n, len(clt.mailboxes))
	keys := make([][]byte, spans[0].End-spans[0].Start)
	for i := range spans {
		numKeys := spans[i].End - spans[i].Start
		mid := mailboxMap[*clt.publicKeys[spans[i].Start]]

		expected := make([]uint64, numKeys)
		for k := range expected {
			key := *clt.publicKeys[spans[i].Start+k]
			expected[k] = uint64(len(clt.assignments[key]))
		}

		for i, key := range clt.publicKeys[spans[i].Start:spans[i].End] {
			keys[i] = (*key)[:]
		}

		streamSpan := span.StreamSpan(numKeys, config.StreamSize, 32)

		stream, err := rpcs[mid].RegisterUsers(context.Background())
		if err != nil {
			return nil, err
		}

		for _, sspan := range streamSpan {
			req := &mailbox.RegisterUsersRequest{
				Round:    in.Round,
				UserKeys: keys[:numKeys][sspan.Start:sspan.End],
				Expected: expected[sspan.Start:sspan.End],
			}

			err := stream.Send(req)
			if err != nil {
				return nil, err
			}
		}
		_, err = stream.CloseAndRecv()
		if err != nil && err != io.EOF {
			return nil, err
		}
	}

	return &RegisterUsersResponse{}, nil
}

func (clt *client) GenerateMessages(ctx context.Context, in *GenerateMessagesRequest) (*GenerateMessagesResponse, error) {
	ciphertexts, prfs, err := clt.generateExperimentMessages(int(in.Round), int(in.MsgSize))
	if err != nil {
		return nil, err
	}

	clt.ciphertexts = ciphertexts
	clt.prfs = prfs

	// uncomment to force memory back, though shouldn't be necessary..
	debug.FreeOSMemory()

	return &GenerateMessagesResponse{}, nil
}

func (clt *client) submitMixRequest(mrpcs map[string]mixnet.MixClient, round uint64, gid string) error {
	ciphertexts := clt.ciphertexts
	prfs := clt.prfs

	errs := make(chan error, len(clt.groups[gid].Servers))

	for i, sid := range clt.groups[gid].Servers {
		go func(i int, sid string) {
			md := metadata.Pairs(
				"id", sid,
				"round", strconv.Itoa(int(round)),
				"source", mixnet.Source_CLIENT.String(),
			)
			ctx := metadata.NewOutgoingContext(context.Background(), md)

			stream, err := mrpcs[sid].SubmitCiphertexts(ctx)
			if err != nil {
				errs <- err
				return
			}

			spans := span.StreamSpan(len(ciphertexts[gid]), config.StreamSize, len(ciphertexts[gid][0])+len(prfs[gid][0]))
			for _, span := range spans {
				req := &mixnet.SubmitCiphertextsRequest{
					Round:       round,
					Ciphertexts: ciphertexts[gid][span.Start:span.End],
					Proofs:      prfs[gid][span.Start:span.End],
				}
				err = stream.Send(req)
				if err != nil {
					log.Println("Client failed to add messge:", err)
					errs <- err
					return
				}
			}

			_, err = stream.CloseAndRecv()
			if err != nil && err != io.EOF {
				log.Println("Stream closing err for AddMessages:", err)
				errs <- err
				return
			}
			errs <- nil
		}(i, sid)
	}

	for range clt.groups[gid].Servers {
		err := <-errs
		if err != nil {
			return err
		}
	}

	return nil
}

func (clt *client) SubmitMessages(ctx context.Context, in *SubmitMessagesRequest) (*SubmitMessagesResponse, error) {
	if clt.ciphertexts == nil {
		return nil, errors.New("Messages not generated yet")
	}

	conns, err := config.DialServers(clt.servers)
	if err != nil {
		return nil, err
	}

	defer config.CloseConns(conns)

	mrpcs := make(map[string]mixnet.MixClient)
	for id, cfg := range clt.servers {
		mrpcs[id] = mixnet.NewMixClient(conns[cfg.Address])
	}

	for gid := range clt.ciphertexts {
		// submit message to mixnet for mixing
		err = clt.submitMixRequest(mrpcs, in.Round, gid)
		if err != nil {
			return nil, err
		}
	}

	clt.ciphertexts = make(map[string][][]byte)
	clt.prfs = make(map[string][][]byte)
	// uncomment to force memory back, though shouldn't be necessary..
	debug.FreeOSMemory()

	return &SubmitMessagesResponse{}, nil
}

func (clt *client) DownloadMessages(ctx context.Context, in *DownloadMessagesRequest) (*DownloadMessagesResponse, error) {
	mailboxMap := clt.mapUsers()

	conns, err := config.DialServers(clt.mailboxes)
	if err != nil {
		return nil, err
	}
	defer config.CloseConns(conns)

	rpcs := make(map[string]mailbox.MailboxClient)
	for mid, cfg := range clt.mailboxes {
		rpcs[mid] = mailbox.NewMailboxClient(conns[cfg.Address])
	}

	spans := span.NSpans(clt.n, len(clt.mailboxes))
	errs := make(chan error, len(spans))

	// send all the fetch requests
	for i := range spans {
		go func(i int) {
			keys := make([][]byte, spans[i].End-spans[i].Start)
			mid := mailboxMap[*clt.publicKeys[spans[i].Start]]

			for i, key := range clt.publicKeys[spans[i].Start:spans[i].End] {
				keys[i] = (*key)[:]
			}

			stream, err := rpcs[mid].GetMails(context.Background())
			if err != nil {
				errs <- err
				return
			}

			go func() { // stream the requests, in case it's too big
				streamSpans := span.StreamSpan(len(keys), config.StreamSize, 32)

				for _, sspan := range streamSpans {
					req := &mailbox.GetMailsRequest{
						Round:    in.Round,
						UserKeys: keys[sspan.Start:sspan.End],
					}
					err := stream.Send(req)
					if err != nil {
						errs <- err
						return
					}
				}
				errs <- stream.CloseSend()
			}()

			// TODO: should check if the received msgs are accurate
			go func() { // get the responses
				for {
					_, err := stream.Recv()
					if err == io.EOF {
						break
					} else if err != nil {
						errs <- err
						return
					}
					errs <- nil
				}
			}()
		}(i)
	}

	for range spans {
		err := <-errs
		if err != nil {
			return nil, err
		}

		err = <-errs
		if err != nil {
			return nil, err
		}
	}

	//log.Println("All mails received")
	debug.FreeOSMemory()

	return &DownloadMessagesResponse{}, nil
}
