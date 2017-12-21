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
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sdk "github.com/bitmark-inc/bitmark-sdk-go"
)

var version = "X.x"

var offsetFile = ".offset"

type bitmark struct {
	ID     string `json:"id"`
	Issuer string `json:"issuer"`
	Offset int    `json:"offset"`
}

func main() {
	init := false
	showVersion := false
	seed := ""
	datadir := ""
	network := ""
	flag.BoolVar(&init, "init", false, "initialize the bitmark")
	flag.BoolVar(&showVersion, "version", false, "show version number")
	flag.StringVar(&seed, "account", "", "Bitmark Account")
	flag.StringVar(&network, "network", "live", "Network")
	flag.StringVar(&datadir, "data-dir", "data", "Directory to store all data")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return
	}

	log.Println("Network:", strings.ToUpper(network))

	if seed == "" {
		log.Fatalln("invalid account")
	}
	core, err := hex.DecodeString(seed)
	if err != nil {
		log.Fatalln("invalid account")
	}

	var n sdk.Network
	if network == "live" {
		n = 0
	} else {
		n = 1
	}

	cfg := &sdk.Config{
		HTTPClient: &http.Client{Timeout: 30 * time.Second}, // For downloading large assets
		Network:    n,
	}

	if network == "devel" {
		cfg.APIEndpoint = "https://api.devel.bitmark.com"
		cfg.KeyEndpoint = "https://key.assets.devel.bitmark.com"
	}
	client := sdk.NewClient(cfg)

	account, err := sdk.AccountFromCore(n, core)
	if err != nil {
		log.Fatalln("Cannot initialize account from seed, error:", err)
	}
	totalBitmarks := 100
	lastOffset := -1
	savedOffset := -1

	for totalBitmarks >= 100 {
		accountPath := filepath.Join(datadir, account.AccountNumber())
		os.MkdirAll(accountPath, 0755)

		savedOffset = readFirstOffset(accountPath)

		// Fetch available assets from API server
		url := cfg.APIEndpoint + "/v1/bitmarks?pending=false&owner=" + account.AccountNumber()
		if lastOffset > 0 {
			url = url + "&at=" + strconv.Itoa(lastOffset)
		}

		log.Println("Fetching bitmarks with url:", url)
		response, err := http.DefaultClient.Get(url)
		if err != nil {
			log.Fatalln("Error when getting data from API server err:", err)
		}

		var bitmarkData struct {
			Bitmarks []bitmark `json:"bitmarks"`
		}

		decoder := json.NewDecoder(response.Body)
		err = decoder.Decode(&bitmarkData)
		if err != nil {
			log.Fatal("Invalid data from API server")
		}

		totalBitmarks = len(bitmarkData.Bitmarks)

		// Save first offset for next time fetching
		if lastOffset == -1 {
			saveFirstOffset(accountPath, bitmarkData.Bitmarks[0].Offset)
		}

		lastOffset = bitmarkData.Bitmarks[totalBitmarks-1].Offset

		// Loop for bitmarks and download
		for i, bitmark := range bitmarkData.Bitmarks {
			if bitmark.Offset <= savedOffset {
				goto Done
			}

			log.Printf("%d/%d Downloading bitmark: %s", i+1, totalBitmarks, bitmark.ID)
			downloadBitmark(client, account, bitmark, datadir)
		}
	}
Done:
	log.Println("Done")
}

func downloadBitmark(client *sdk.Client, account *sdk.Account, b bitmark, datadir string) {
	_, assetBytes, err := client.DownloadAsset(account, b.ID)
	if err != nil {
		log.Println("Cannot download bitmark data: err:", err)
	} else {
		// unarchive the donor data
		donorDatabuf := bytes.NewReader(assetBytes)
		unzipper, err := zip.NewReader(donorDatabuf, int64(donorDatabuf.Len()))
		if err != nil {
			log.Fatal(err)
		}

		datapath := filepath.Join(datadir, account.AccountNumber(), b.Issuer, b.ID)
		os.MkdirAll(datapath, 0755)
		for _, srcFile := range unzipper.File {
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

func saveFirstOffset(path string, offset int) {
	os.MkdirAll(path, 0755)
	p := filepath.Join(path, offsetFile)
	fo, err := os.Create(p)
	if err != nil {
		log.Fatal(err)
	}
	defer fo.Close()

	s := strconv.Itoa(offset)

	_, err = io.Copy(fo, strings.NewReader(s))
	if err != nil {
		log.Fatal(err)
	}
}

func readFirstOffset(path string) int {
	p := filepath.Join(path, offsetFile)
	data, err := ioutil.ReadFile(p)
	if err != nil {
		return -1
	}

	offsetString := string(data)
	offset, err := strconv.Atoi(offsetString)
	if err != nil {
		return -1
	}
	return offset
}
