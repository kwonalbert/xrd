package mailbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
	grpc "google.golang.org/grpc"
)

var mailboxAddr = "localhost:8500"
var port = ":8500"

func TestBasicMailbox(t *testing.T) {
	server := NewMailboxServer(ecdsa.PublicKey{})

	go func() {
		grpcServer := grpc.NewServer()
		RegisterMailboxServer(grpcServer, server)

		lis, err := net.Listen("tcp", port)
		if err != nil {
			log.Fatal("Could not listen:", err)
		}

		err = grpcServer.Serve(lis)
		if err != grpc.ErrServerStopped {
			log.Fatal("Serve err:", err)
		}
	}()

	time.Sleep(time.Millisecond)

	cc, err := grpc.Dial(mailboxAddr, grpc.WithInsecure())
	if err != nil {
		panic("Couldn't dial mailbox")
	}
	mailbox := NewMailboxClient(cc)

	_, err = mailbox.NewRound(context.Background(), &NewRoundRequest{0})
	if err != nil {
		t.Error(err)
	}

	numUsers := 10
	msgsPerUser := 5

	var nonce [24]byte
	binary.PutUvarint(nonce[:], 0)

	pubs, privs := make([]*[32]byte, numUsers), make([]*[32]byte, numUsers)
	keys := make([][]byte, numUsers)
	for i := range pubs {
		pubs[i], privs[i], err = box.GenerateKey(rand.Reader)
		if err != nil {
			panic("Could not create keys")
		}
		keys[i] = (*pubs[i])[:]
	}

	msgs := make([][][]byte, numUsers)
	mails := make([]*Mail, numUsers*msgsPerUser)
	for i := range msgs {
		msgs[i] = make([][]byte, msgsPerUser)
		for j := range msgs[i] {
			msgs[i][j] = make([]byte, 100)
			rand.Read(msgs[i][j])
			mails[i*msgsPerUser+j] = SealMail(pubs[i], &nonce, msgs[i][j])
		}
	}

	expected := make([]uint64, len(keys))
	for e := range expected {
		expected[e] = uint64(msgsPerUser)
	}

	regReq := &RegisterUsersRequest{
		Round:    0,
		UserKeys: keys,
		Expected: expected,
	}
	stream, err := mailbox.RegisterUsers(context.Background())
	if err != nil {
		t.Error(err)
	}
	err = stream.Send(regReq)
	if err != nil {
		t.Error(err)
	}
	_, err = stream.CloseAndRecv()
	if err != nil && err != io.EOF {
		t.Error(err)
	}

	deliverReq := &DeliverMailsRequest{
		Round: 0,
		Mails: mails,
	}

	outStream, err := mailbox.DeliverMails(context.Background())
	if err != nil {
		t.Error(err)
	}

	err = outStream.Send(deliverReq)
	if err != nil {
		t.Error(err)
	}

	getReq := &GetMailsRequest{
		Round:    0,
		UserKeys: keys,
	}
	inStream, err := mailbox.GetMails(context.Background(), getReq)
	if err != nil {
		t.Error(err)
	}

	total := 0
	for {
		resp, err := inStream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}

		for i, inbox := range resp.Inboxes {
			for _, mail := range inbox.Messages {
				msg := OpenMail(privs[i], &nonce, mail)

				found := false
				for j := range msgs[i] {
					if bytes.Equal(msgs[i][j], msg) {
						found = true
						break
					}
				}
				if !found {
					t.Error("Unexpected messages")
				}
				total += 1
			}
		}
	}

	if total != numUsers*msgsPerUser {
		t.Error("Not enough messages")
	}
}
