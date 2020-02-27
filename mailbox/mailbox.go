package mailbox

import (
	"crypto/ecdsa"
	"errors"
	"io"
	"sync"

	"github.com/kwonalbert/xrd/config"
	"github.com/kwonalbert/xrd/span"
	
	"golang.org/x/net/context"
)

type mailbox struct {
	coordinator ecdsa.PublicKey

	smu    sync.RWMutex
	states map[uint64]*roundState
}

type roundState struct {
	mu       sync.RWMutex
	inboxes  map[[32]byte][][]byte
	inboxwgs map[[32]byte]*sync.WaitGroup
}

func NewMailboxServer(coordinator ecdsa.PublicKey) MailboxServer {
	mb := &mailbox{
		coordinator: coordinator,

		states: make(map[uint64]*roundState),
	}
	return mb
}

// only coordinator is allowed to call NewRound, EndRound, and Mix on the first server
// TODO: Add authentication for all functions

func (mb *mailbox) NewRound(ctx context.Context, in *NewRoundRequest) (*NewRoundResponse, error) {
	state := &roundState{
		inboxes:  make(map[[32]byte][][]byte),
		inboxwgs: make(map[[32]byte]*sync.WaitGroup),
	}
	mb.smu.Lock()
	mb.states[in.Round] = state
	mb.smu.Unlock()
	return &NewRoundResponse{}, nil
}

func (mb *mailbox) EndRound(ctx context.Context, in *EndRoundRequest) (*EndRoundResponse, error) {
	mb.smu.Lock()
	delete(mb.states, in.Round)
	mb.smu.Unlock()
	return &EndRoundResponse{}, nil
}

func (mb *mailbox) RegisterUsers(stream Mailbox_RegisterUsersServer) error {
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		mb.smu.RLock()
		state, ok := mb.states[in.Round]
		mb.smu.RUnlock()
		if !ok {
			return errors.New("Round not initialized")
		}

		var tmpKey [32]byte
		state.mu.Lock()
		for i, key := range in.UserKeys {
			copy(tmpKey[:], key)
			state.inboxes[tmpKey] = nil
			wg := new(sync.WaitGroup)
			wg.Add(int(in.Expected[i]))
			state.inboxwgs[tmpKey] = wg
		}
		state.mu.Unlock()
	}
	return nil
}

func (mb *mailbox) RegisteredUsers(in *RegisteredUsersRequest, stream Mailbox_RegisteredUsersServer) error {
	mb.smu.RLock()
	state, ok := mb.states[in.Round]
	mb.smu.RUnlock()
	if !ok {
		return errors.New("Round not initialized")
	}

	keys := make([][]byte, len(state.inboxes))
	state.mu.RLock()
	i := 0
	for key := range state.inboxes {
		keys[i] = make([]byte, 32)
		// TODO: seems to be a weird bug, when you assign keys[i] = key[:],
		// the keys[j] changes to for j < i. maybe my misunderstanding of
		// for loops and array as keys..?
		copy(keys[i], key[:])
		i++
	}
	state.mu.RUnlock()

	spans := span.StreamSpan(len(keys), config.StreamSize, 32)
	for _, span := range spans {
		if err := stream.Send(&RegisteredUsersResponse{
			UserKeys: keys[span.Start:span.End],
		}); err != nil {
			return err
		}
	}

	return nil
}

func (mb *mailbox) DeliverMails(stream Mailbox_DeliverMailsServer) error {
	var tmpKey [32]byte

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		mb.smu.RLock()
		state, ok := mb.states[req.Round]
		mb.smu.RUnlock()
		if !ok {
			return errors.New("Round not initialized")
		}

		state.mu.Lock()
		for _, mail := range req.Mails {
			copy(tmpKey[:], mail.UserKey)
			box, ok := state.inboxes[tmpKey]
			if !ok {
				return errors.New("Userkey not registered")
			}
			state.inboxes[tmpKey] = append(box, mail.Message)
			state.inboxwgs[tmpKey].Done()
		}
		state.mu.Unlock()
	}
	return nil
}

func (mb *mailbox) GetMails(stream Mailbox_GetMailsServer) error {
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		mb.smu.RLock()
		state, ok := mb.states[in.Round]
		mb.smu.RUnlock()
		if !ok {
			return errors.New("Round not initialized")
		}

		var tmpKey [32]byte

		// get the first one so we can configure the stream
		for _, key := range in.UserKeys {
			copy(tmpKey[:], key)
			state.mu.RLock()
			wg, ok := state.inboxwgs[tmpKey]
			state.mu.RUnlock()
			if !ok {
				return errors.New("Userkey not registered")
			}
			wg.Wait()
		}
		//log.Println("All mails present")

		state.mu.RLock()
		msgSize := len(state.inboxes[tmpKey]) * len(state.inboxes[tmpKey][0])
		state.mu.RUnlock()
		spans := span.StreamSpan(len(in.UserKeys), config.StreamSize, msgSize)

		for _, span := range spans {
			inboxes := make([]*Inbox, span.End-span.Start)
			for i, key := range in.UserKeys[span.Start:span.End] {
				copy(tmpKey[:], key)
				state.mu.RLock()
				wg, ok := state.inboxwgs[tmpKey]
				state.mu.RUnlock()
				if !ok {
					return errors.New("Userkey not registered")
				}
				wg.Wait()
				state.mu.RLock()
				inbox := state.inboxes[tmpKey]
				state.mu.RUnlock()
				inboxes[i] = &Inbox{
					UserKey:  key,
					Messages: inbox,
				}
			}
			if err := stream.Send(&GetMailsResponse{
				Inboxes: inboxes,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}
