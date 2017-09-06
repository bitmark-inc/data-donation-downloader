package main

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bitmark-inc/bitmarkd/util"
	"github.com/bitmark-inc/go-bitmarklib"
	"github.com/lemonlatte/go-registry"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	seedNonce = [24]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	authSeedCountBM = [16]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe7,
	}
	encrSeedCountBM = [16]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8,
	}
)

var version = "X.x"

var (
	bitmarkApiUrl     = ""
	bitmarkStorageUrl = ""
)

type TokenReqBody struct {
	Account   string `json:"account"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type Provenance struct {
	TxId      string `json:"tx_id"`
	Owner     string `json:"owner"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type Bitmark struct {
	Id         string       `json:"id"`
	HeadId     string       `json:"head_id"`
	Owner      string       `json:"owner"`
	Issuer     string       `json:"issuer"`
	Head       string       `json:"head"`
	Status     string       `json:"status"`
	Provenance []Provenance `json:"provenance"`
}

func NewSeedFromHexString(seed string) ([32]byte, error) {
	rootSeed := [32]byte{}
	b, err := hex.DecodeString(seed)
	if err != nil {
		return rootSeed, err
	}

	if len(b) != 32 {
		return rootSeed, fmt.Errorf("invalid length of bitmark account")
	}
	copy(rootSeed[:], b[:32])
	return rootSeed, nil
}

func registerEncKey(authKey *bitmarklib.KeyPair, encKey *bitmarklib.EncrKeyPair) error {
	accountNo := authKey.Account().String()
	signatureOrigin := ed25519.Sign(authKey.PrivateKeyBytes(), encKey.PublicKey[:])
	signature := hex.EncodeToString(signatureOrigin)

	encKeyUrl := fmt.Sprintf("%s/v1/encryption_keys/%s", bitmarkApiUrl, accountNo)

	encryptPubKey := hex.EncodeToString(encKey.PublicKey[:])

	req := map[string]string{
		"encryption_pubkey": encryptPubKey,
		"signature":         signature,
	}

	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	err := e.Encode(req)
	if err != nil {
		return err
	}

	log.Println("Check the encryption key here: ", encKeyUrl)
	resp, err := http.Post(encKeyUrl, "application/json", &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body := map[string]string{}
		d := json.NewDecoder(resp.Body)
		d.Decode(&body)
		return fmt.Errorf(body["message"])
	}
	return nil
}

func getEncryptionKey(accountNo string) ([32]byte, error) {
	encKey := [32]byte{}

	encKeyUrl := fmt.Sprintf("%s/v1/encryption_keys/%s", bitmarkApiUrl, accountNo)
	resp, err := http.Get(encKeyUrl)
	if err != nil {
		return encKey, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return encKey, err
	}

	var respBody map[string]string
	d := json.NewDecoder(resp.Body)
	err = d.Decode(&respBody)
	if err != nil {
		return encKey, err
	}
	senderKeyBytes, err := hex.DecodeString(respBody["encryption_pubkey"])
	if err != nil {
		return encKey, err
	}

	copy(encKey[:], senderKeyBytes)
	return encKey, nil
}

func getSessionData(bitmarkId, owner string) (*bitmarklib.SessionData, error) {
	sessionData := &bitmarklib.SessionData{}
	sessionUrl, err := url.Parse(fmt.Sprintf("%s/v1/session/%s", bitmarkApiUrl, bitmarkId))
	if err != nil {
		return nil, err
	}
	v := url.Values{}
	v.Set("account_no", owner)
	sessionUrl.RawQuery = v.Encode()

	resp, err := http.Get(sessionUrl.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("session data request status not ok")
	}

	d := json.NewDecoder(resp.Body)
	err = d.Decode(&sessionData)
	if err != nil {
		return nil, err
	}

	return sessionData, nil
}

func getStorageAccessToken(authKeyPair *bitmarklib.KeyPair) (string, error) {
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	tokenReqUrl := fmt.Sprintf("%s/s/api/token", bitmarkStorageUrl)
	tokenReq := TokenReqBody{
		Account:   authKeyPair.Account().String(),
		Timestamp: ts,
		Signature: hex.EncodeToString(ed25519.Sign(authKeyPair.PrivateKeyBytes(), []byte(ts))),
	}

	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	err := e.Encode(&tokenReq)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(tokenReqUrl, "application/json", &buf)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token request is not ok")
	}
	var body map[string]string

	d := json.NewDecoder(resp.Body)
	err = d.Decode(&body)
	if err != nil {
		return "", err
	}
	token, ok := body["token"]
	if !ok {
		return "", fmt.Errorf("no token found in response")
	}
	return token, nil
}

func getEncryptedFile(bitmarkId, token string) ([]byte, error) {
	encFileGetUrl := fmt.Sprintf("%s/s/assets/%s?token=%s", bitmarkStorageUrl, bitmarkId, token)
	resp, err := http.Get(encFileGetUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	encrpytedFileBytes, err := ioutil.ReadAll(resp.Body)
	return encrpytedFileBytes, err
}

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	init := false
	showVersion := false
	seed := ""
	datadir := ""
	network := ""
	flag.BoolVar(&init, "init", false, "initialize the bitmark")
	flag.BoolVar(&showVersion, "version", false, "show version number")
	flag.StringVar(&seed, "account", "", "Bitmark Account")
	flag.StringVar(&network, "network", "", "Network")
	flag.StringVar(&datadir, "data-dir", "data", "Directory to store all data")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return
	}

	log.Printf("Network: %s", strings.ToUpper(network))
	inTest := false
	switch network {
	case "devel":
		bitmarkApiUrl = "https://api.devel.bitmark.com"
		bitmarkStorageUrl = "https://storage.devel.bitmark.com"
		inTest = true
	case "test":
		bitmarkApiUrl = "https://api.test.bitmark.com"
		bitmarkStorageUrl = "https://assets.test.bitmark.com"
		inTest = true
	default:
		bitmarkApiUrl = "https://api.bitmark.com"
		bitmarkStorageUrl = "https://assets.bitmark.com"
	}

	if seed == "" {
		log.Fatal("invalid account")
	}

	rootSeed, err := NewSeedFromHexString(seed)
	if err != nil {
		log.Fatalf("Fail to generate root seed: %s", err.Error())
	}

	authSeed := secretbox.Seal([]byte{}, authSeedCountBM[:], &seedNonce, &rootSeed)
	authKeyPair, err := bitmarklib.NewKeyPairFromSeed(authSeed, inTest, bitmarklib.ED25519)
	if err != nil {
		log.Fatalf("Fail to generate account key: %s", err.Error())
	}
	log.Printf("Auth Account: %s", authKeyPair.Account().String())

	encSeed := secretbox.Seal([]byte{}, encrSeedCountBM[:], &seedNonce, &rootSeed)
	encKeyPair, err := bitmarklib.NewEncrKeyPairFromSeed(encSeed[:])
	if err != nil {
		log.Fatalf("Fail to generate encryption key: %s", err.Error())
	}
	log.Printf("Enc Public Key: %s", strings.ToUpper(hex.EncodeToString(encKeyPair.PublicKey[:])))

	if init {
		err := registerEncKey(authKeyPair, encKeyPair)
		if err != nil {
			log.Errorf("can not register encryption key: %s", err.Error())
		} else {
			log.Info("account registered")
		}
		return
	}

	// fetch all bitmarks belong to the account
	regClient, err := registry.New(bitmarkApiUrl)
	if err != nil {
		log.Fatalf("can not create a registry client: %s", err.Error())
	}
	b, err := regClient.GetBitmarkByOwner(authKeyPair.Account().String(), false, false)
	if err != nil {
		log.Fatalf("can not get bitmarks from registry: %s", err.Error())
	}
	var bitmarks []Bitmark
	err = json.Unmarshal(b, &bitmarks)
	if err != nil {
		log.Fatalf("fail to decode registry data: %s", err.Error())
	}

	if len(bitmarks) == 0 {
		log.Println("No data found")
		return
	}

	// for each possible bitmarks, download and extract it.
	log.Println("Start fetching donor data...")
	for _, bmk := range bitmarks {
		log.Printf("Get data with bitmark id: %s", bmk.Id)
		// FIXME: remove the additional request if
		// the registery supports `previous_owner` in the future
		b, err := regClient.GetBitmark(bmk.Id, false, true)
		if err != nil {
			log.Fatalf("can not get bitmarks from registry: %s", err.Error())
		}

		err = json.Unmarshal(b, &bmk)
		if err != nil {
			log.Fatalf("fail to decode registry data: %s", err.Error())
		}
		if bmk.Owner == bmk.Issuer {
			log.Printf("omit bitmark id: %s. I am the issuer", bmk.Id)
			continue
		}

		// The items of the provenance is in descending order
		senderAccountNo := bmk.Provenance[1].Owner

		// Get encryption key
		senderEncPubKey, err := getEncryptionKey(senderAccountNo)
		if err != nil {
			log.Printf("can not get the encryption key for an account. error: %s", err.Error())
			continue
		}

		// Get session data
		sessionData, err := getSessionData(bmk.Id, bmk.Owner)
		if err != nil {
			log.Warnf("fail to request session data. error: %s", err.Error())
			continue
		}

		senderPubKey, err := bitmarklib.NewPublicKey(util.FromBase58(senderAccountNo))
		if err != nil {
			log.Warnf("fail to generate sender public key: %s", err.Error())
			continue
		}

		// Decrypt session key
		sessionKey, err := bitmarklib.SessionKeyFromSessionData(sessionData,
			&senderEncPubKey, encKeyPair.PrivateKey,
			senderPubKey.PublicKeyBytes())
		if err != nil {
			log.Warnf("unable to decrypt session data: %s", err.Error())
			continue
		}

		token, err := getStorageAccessToken(authKeyPair)
		if err != nil {
			log.Warnf("unable to get storage token: %s", err.Error())
			continue
		}

		encryptedFileBytes, err := getEncryptedFile(bmk.Id, token)
		if err != nil {
			log.Warnf("unable to get donor data: %s", err.Error())
			continue
		}

		// Decrypt
		donorData, err := bitmarklib.DecryptAssetFile(encryptedFileBytes, sessionKey,
			senderPubKey.PublicKeyBytes())
		if err != nil {
			log.Warnf("unable to decrypt donor data: %s", err.Error())
			continue
		}

		// unarchive the donor data
		donorDatabuf := bytes.NewReader(donorData)
		unzipper, err := zip.NewReader(donorDatabuf, int64(donorDatabuf.Len()))
		if err != nil {
			log.Fatal(err)
		}

		for _, srcFile := range unzipper.File {
			datapath := filepath.Join(datadir, bmk.Issuer, bmk.Id)
			os.MkdirAll(datapath, 0755)

			p := filepath.Join(datapath, srcFile.Name)
			if srcFile.FileInfo().IsDir() {
				os.MkdirAll(p, srcFile.Mode())
			} else {
				destFile, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
				if err != nil {
					log.Fatal(err)
				}

				sf, err := srcFile.Open()
				if err != nil {
					log.Fatal(err)
				}

				_, err = io.Copy(destFile, sf)
				if err != nil {
					log.Fatal(err)
				}
				sf.Close()
			}
		}
	}
}
