package elliptic

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func ExampleRecreateSharedSecret() {

	type message struct {
		ciphertext []byte
		nonce      []byte
	}

	// AES encryption
	encrypt := func(msg, key []byte) (*message, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		return &message{
			ciphertext: aesgcm.Seal(nil, nonce, msg, nil),
			nonce:      nonce,
		}, nil
	}

	// AES decryption
	decrypt := func(msg *message, key []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return aesgcm.Open(nil, msg.nonce, msg.ciphertext, nil)
	}

	type communicatorID []byte

	type messageHandler func(received []byte) ([]byte, bool)
	type channelHandler func(context.Context, []byte, messageHandler)
	type dialer func(context.Context, *PublicKey, chan *message) (chan *message, error)

	type idinfo struct {
		dialer dialer
		curve  Curve
		pubKey *PublicKey
	}

	type getInfo func(communicatorID) ([]*idinfo, error)
	type connector func(context.Context, communicatorID, getInfo) (channelHandler, error)

	type updateInfo func(Curve, *PublicKey, time.Time)
	type registration func(communicatorID, dialer) (updateInfo, error)

	colin := func(ctx context.Context, reviewInterval time.Duration) (registration, getInfo) {

		type info struct {
			keyInfo *idinfo
			expiry  time.Time
		}

		idToString := func(id communicatorID) string { return hex.EncodeToString([]byte(id)) }

		var d = map[string]dialer{}
		var m = map[string][]*info{}
		var lck sync.RWMutex

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(reviewInterval):
					// trigger expiry check
				}

				var newM = map[string][]*info{}
				{
					lck.RLock()
					defer lck.RUnlock()

					// create new map, pruning expired info
					for k, v := range m {
						newI := []*info{}
						for _, vv := range v {
							if vv.expiry.After(time.Now().UTC()) {
								newI = append(newI, vv)
							}
						}
						newM[k] = newI
					}
				}

				// Now switch as a single write action
				lck.Lock()
				defer lck.Unlock()
				m = newM
			}
		}()

		return func(id communicatorID, dialer dialer) (updateInfo, error) {
				s := idToString(id)

				lck.Lock()
				defer lck.Unlock()

				if _, ok := d[s]; ok {
					return nil, errors.New("cannot re-register")
				}

				d[s] = dialer
				m[s] = []*info{}

				return func(curve Curve, pubKey *PublicKey, expiry time.Time) {
					t := expiry.UTC()
					if t.Before(time.Now().UTC()) {
						return
					}

					s := idToString(id)

					lck.Lock()
					defer lck.Unlock()

					var i []*info
					var ok bool
					if i, ok = m[s]; !ok {
						i = []*info{}
					}
					i = append(i, &info{
						keyInfo: &idinfo{
							curve:  curve,
							pubKey: pubKey,
						},
						expiry: t,
					})

					m[s] = i
				}, nil
			},
			func(id communicatorID) ([]*idinfo, error) {

				s := idToString(id)

				lck.RLock()
				defer lck.RUnlock()

				if i, ok := m[s]; !ok {
					return nil, errors.New("unknown identity")
				} else {
					dialer := d[s]
					ii := []*idinfo{}

					for _, v := range i {
						if v.expiry.After(time.Now().UTC()) {
							ii = append(ii, &idinfo{
								dialer: dialer,
								curve:  v.keyInfo.curve,
								pubKey: v.keyInfo.pubKey,
							})
						}
					}

					return ii, nil
				}
			}
	}

	communicator := func(ctx context.Context, register registration, resetInterval time.Duration, dialedHandler messageHandler) ([]byte, connector) {

		// Id of this communicator
		b := make([]byte, 32)
		rand.Read(b)
		var hash []byte = sha256.New().Sum(b)
		id := make([]byte, hex.EncodedLen(len(hash)))
		hex.Encode(id, hash)

		// Current key materials of this communicator
		var privKey *PrivateKey
		var pkLck sync.RWMutex

		// Manage symmetric encryption and handling of decrypted message
		handler := func(m *message, key []byte, handle messageHandler) (*message, bool) {
			if m == nil {
				panic("handler: m is nil")
			}
			if len(key) == 0 {
				panic("handler: no key")
			}
			if handle == nil {
				panic("handler: no handle")
			}
			received, _ := decrypt(m, key)
			response, ok := handle(received)
			if !ok {
				// Signaled end of communication
				return nil, ok
			}
			reply, _ := encrypt(response, key)
			return reply, true
		}

		// Both parties in a communication operate the same way, listening to a chan and replying on their own
		responder := func(ctx context.Context, receiverChan, senderChan chan *message, key []byte, h messageHandler) {
			defer close(senderChan)

			for {
				select {
				case <-ctx.Done():
					return
				case m, ok := <-receiverChan:
					if !ok {
						return
					}
					m, ok = handler(m, key, h)
					if !ok {
						return
					}
					senderChan <- m
				}
			}
		}

		// The dialer that can be used to initiate communcation with this communicator
		dialer := func(ctx context.Context, pubKey *PublicKey, receiveChan chan *message) (chan *message, error) {

			var pk *PrivateKey

			// Lock for as little time as require
			{
				pkLck.RLock()
				defer pkLck.RUnlock()
				pk = privKey
			}

			oneTimeSecret, err := RecreateSharedSecret(pk, pubKey)
			if err != nil {
				panic(fmt.Errorf("dialer: err: %v", err))
			}

			sendChan := make(chan *message)

			go responder(ctx, receiveChan, sendChan, oneTimeSecret, dialedHandler)

			return sendChan, nil
		}

		// Register the existence of this communicator
		updater, err := register(id, dialer)
		if err != nil {
			panic(err)
		}

		reset := func() {
			var pk *PrivateKey

			// Lock for as little time as require
			{
				pkLck.Lock()
				defer pkLck.Unlock()

				var err error
				privKey, err = NewPrivateKey(p256)
				if err != nil {
					panic(fmt.Errorf("reset: err: %v", err))
				}

				pk = privKey
			}

			// Ensure Colin gets the new details
			updater(pk.Curve(), pk.PublicKey(), time.Now().UTC().Add(resetInterval))
		}

		// Give initial key to Colin
		reset()

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(resetInterval):
					// trigger new key generation
				}

				reset()

			}
		}()

		return id,
			func(ctx context.Context, receiverID communicatorID, registry getInfo) (channelHandler, error) {

				// Retrieve idinfo for the receiver
				i, err := registry(receiverID)
				if err != nil {
					return nil, err
				}
				if len(i) == 0 {
					return nil, errors.New("no connection info")
				}

				// Construct one-time details to be shared, based on latest idinfo
				ii := i[len(i)-1]
				oneTimePriKey, oneTimeSecret, err := NewSharedSecret(ii.pubKey)
				if err != nil {
					panic(fmt.Errorf("oneTimeKey: err: %v", err))
				}

				// Dial the receiver, and hopefully receive inbound chan
				sendChan := make(chan *message)
				receiveChan, err := ii.dialer(ctx, oneTimePriKey.PublicKey(), sendChan)
				if err != nil {
					return nil, err
				}

				return func(ctx context.Context, initialMessage []byte, h messageHandler) {
					// Send initial message
					m, _ := encrypt(initialMessage, oneTimeSecret)
					sendChan <- m

					// Start interaction
					responder(ctx, receiveChan, sendChan, oneTimeSecret, h)
				}, nil
			}
	}

	// Uncomment this if the example looks to have frozen, so that output can be observed
	// ctx, cancelTimeout := context.WithTimeout(context.Background(), 2*time.Second)
	// defer cancelTimeout()

	ctx, cancel := context.WithCancel(context.Background())

	// Colin is here to help Alice and Bob communicate
	// He decides to review key expiry every 10 seconds
	registerWithColin, getFromColin := colin(ctx, 10*time.Second)

	// Here is Alice; since no one dials her, no need for a dialed response handler
	// She is going to refresh her keys every minute
	_, aliceDials := communicator(ctx, registerWithColin, 1*time.Minute, nil)

	// This is how Bob handles inbound requests from connections started by someone else
	bobDialedResponsebHandler := func(msg []byte) ([]byte, bool) {
		return msg, true // here just reflect and say to maintain the comms
	}

	// Here is Bob, with his dialed response in place
	// He will refresh his keys every 20 seconds
	bobID, _ := communicator(ctx, registerWithColin, 20*time.Second, bobDialedResponsebHandler)

	// Alice decides to say hi and dials Bob, finding his current details from Colin
	connToBob, err := aliceDials(ctx, bobID, getFromColin)
	if err != nil {
		fmt.Println(err)
		cancel()
		return
	}

	// This is how Alice will handle messages from this specific connection to Bob
	aliceSpecificHandlerToBob := func(msg []byte) ([]byte, bool) {
		fmt.Println(string(msg))
		time.AfterFunc(100*time.Millisecond, cancel) // so we don't wait on the context for ever
		return nil, false                            // signifies all done
	}

	// Alice initiates her conversation with Bob, handling his responses
	connToBob(ctx, []byte("Hello World"), aliceSpecificHandlerToBob)

	// Since we are using goroutines, we want the example to wait on the context
	// until Alice has received her response from Bob, after which she cancels the context
	<-ctx.Done()

	// Output: Hello World
}

func ExampleNewSharedSecret() {

	receiver := func() (*PublicKey, func(pub *PublicKey) ([]byte, error)) {

		privKey, _ := NewPrivateKey(p256)

		return privKey.PublicKey(), func(pub *PublicKey) ([]byte, error) {
			return RecreateSharedSecret(privKey, pub)
		}
	}

	sender := func(reciverPubKey *PublicKey) (*PrivateKey, []byte, error) {
		return NewSharedSecret(reciverPubKey)
	}

	// Run the process several times
	type secrets struct {
		receiver []byte
		sender   []byte
	}

	// Published by the receiver
	receiverPubKey, receiverSecretBinder := receiver()

	results := []*secrets{}

	for i := 0; i < 2; i++ {
		// Created as one-time items by the sender
		senderPrivKey, senderSecret, _ := sender(receiverPubKey)

		// Receiver should be able to create the same one-time secret from the sender's one-time public key
		receiverSecret, _ := receiverSecretBinder(senderPrivKey.PublicKey())

		results = append(results, &secrets{
			receiver: receiverSecret,
			sender:   senderSecret,
		})
	}

	// Without access to each others details, we can see that they generate the same secret
	fmt.Println(bytes.Equal(results[0].receiver, results[0].sender))

	// Which is conveniently the 32 bytes long, i.e. a suitable length for AES encryption
	fmt.Println(len(results[0].receiver) == 2*aes.BlockSize)

	// Also that each secret us unique, since the sender creates new keys each time, against the same receiver details
	fmt.Println(bytes.Equal(results[0].receiver, results[1].receiver))

	// Output: true
	// true
	// false
}

func ExamplePrivateKey_Marshal() {

	der := []byte(`{"i":"AZAq+lK6d0y2SOYveK9Bcg","k":"MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAqEaO+nyVn5KSQJVbWeNdsL0vBUSGDbCFGOV2xEzfwqXGTtj6X1SMaXB25yY5tmbqhZANiAAQ7CH6FUq8kisQraFtqFEvqsssX5zAOZpD0ZUIx3t8Y4NtHMjzpEic29ataZxrAjb9IQ4/AEmk64x5b3BSs5cbskOtUtK/dmeD/SuU9skbweGQLs8BiDVp9nTW8EQO3ujc"}`)
	key, _ := UnMarshalPrivateKey(der)

	b, _ := key.Marshal()

	key2, _ := UnMarshalPrivateKey(b)

	// Show round trip serialisation is the same
	fmt.Println(bytes.Equal(der, b))

	// In particular, show that the ID is preserved
	equal := true
	keyID := key.ID()
	key2ID := key2.ID()
	for i := 0; equal && i < PrivateKeyIDLength; i++ {
		equal = (keyID[i] == key2ID[i])
	}
	fmt.Println(equal)

	// Output: true
	// true
}

func TestUnMarshalPrivateKey(t *testing.T) {

	// Me creating my keys - I share my PublicKey to you
	var remotePriBytes []byte
	var remotePubBytes []byte
	var err error
	{
		remotelPriKey, err := NewPrivateKey(p384)
		if err != nil {
			t.Fatal(err)
		}
		remotePriBytes, err = remotelPriKey.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		remotePubBytes, err = remotelPriKey.PublicKey().Marshal()
		if err != nil {
			t.Fatal(err)
		}
	}

	// You generating the secret using my PublicKey
	var localPubBytes []byte
	var secret []byte
	{
		remotePubKey, err := UnMarshalPublicKey(remotePubBytes)
		if err != nil {
			t.Fatal(err)
		}

		var oneTimePrivKey *PrivateKey
		oneTimePrivKey, secret, err = NewSharedSecret(remotePubKey)
		if err != nil {
			t.Fatal(err)
		}

		localPubBytes, err = oneTimePrivKey.PublicKey().Marshal()
		if err != nil {
			t.Fatal(err)
		}
	}

	// Me recreating your secret with my PrivateKey and your one-time PublicKey
	localPrivKey, err := UnMarshalPrivateKey(remotePriBytes)
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey, err := UnMarshalPublicKey(localPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	recreatedSecret, err := RecreateSharedSecret(localPrivKey, remotePubKey)
	if err != nil {
		t.Fatal(err)
	}

	// Should match!
	if !bytes.Equal(secret, recreatedSecret) {
		t.Fatal("secrets don't match")
	}
}

func TestPrivateKey_Sign(t *testing.T) {

	privKey, err := NewPrivateKey(p256)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("The lazy Fox slept")

	sig, err := privKey.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	pubKey := privKey.PublicKey()

	ok, err := pubKey.Verify(sig, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("Failed to verify signature")
	}
}
