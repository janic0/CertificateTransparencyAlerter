package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
	"gopkg.in/yaml.v3"
)

var CT_FETCH_INTERVAL = 30 * time.Minute
var CT_INITIAL_TIMEOUT = time.Minute
var CT_FAIL_TIMEOUT = 5 * time.Minute
var CONFIG_LOAD_INTERVAL = time.Minute

type Entry struct {
	LeafInput ctgo.LeafInput `json:"leaf_input"`
	ExtraData string         `json:"extra_data"`
}

type Message struct {
	Title   string
	Message string
}

type ConfigFormat struct {
	Logs    []string
	Queries []string
}

var MessageQueue = make(chan Message)

var TargetDefinition = struct {
	Queries []string
	Logs    []string
	Mutex   sync.Mutex
}{}
var PushoverApiKey = os.Getenv("PUSHOVER_API_KEY")
var PushoverUserKey = os.Getenv("PUSHOVER_USER_KEY")

func getSTH(root string) (int64, error) {
	req, err := http.NewRequest("GET", root+"/ct/v1/get-sth", nil)
	req.Header.Add("user-agent", "github.com/janic0/CertificateTransparencyAlerter")

	if err != nil {
		return 0, err
	}
	rq, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	responseText, err := io.ReadAll(rq.Body)
	if err != nil {
		return 0, err
	}

	decodedResponse := struct {
		TreeSize int64 `json:"tree_size"`
	}{}
	err = json.Unmarshal(responseText, &decodedResponse)
	if err != nil {
		return 0, err
	}
	return decodedResponse.TreeSize, nil
}

func getEntries(root string, start int64, end int64) ([]ctgo.LeafEntry, error) {
	req, err := http.NewRequest("GET", root+"/ct/v1/get-entries", nil)
	req.Header.Add("user-agent", "github.com/janic0/CertificateTransparencyAlerter")
	if err != nil {
		return make([]ctgo.LeafEntry, 0), err
	}
	query := req.URL.Query()
	query.Add("start", strconv.Itoa(int(start)))
	query.Add("end", strconv.Itoa(int(end)))
	req.URL.RawQuery = query.Encode()
	rq, err := http.DefaultClient.Do(req)
	if err != nil {
		return make([]ctgo.LeafEntry, 0), err
	}
	responseText, err := io.ReadAll(rq.Body)
	if err != nil {
		return make([]ctgo.LeafEntry, 0), err
	}

	decodedResponse := struct {
		Entries []ctgo.LeafEntry `json:"entries"`
	}{}
	err = json.Unmarshal(responseText, &decodedResponse)
	if err != nil {
		return decodedResponse.Entries, err
	}
	return decodedResponse.Entries, nil
}

func runLoop() {
	// Wait for config to be loaded.
	time.Sleep(1 * time.Second)
	lastTreeSizes := make(map[string]int64)
	for true {
		TargetDefinition.Mutex.Lock()
		for _, log := range TargetDefinition.Logs {
			treeSize, err := getSTH(log)
			lastTreeSize := lastTreeSizes[log]
			if err != nil {
				fmt.Printf("Failed to get STH @ %s: %s\n", log, err.Error())
				time.Sleep(CT_FAIL_TIMEOUT)
				continue
			}
			if lastTreeSize == 0 {
				lastTreeSizes[log] = treeSize
				time.Sleep(CT_INITIAL_TIMEOUT)
				continue
			}

			entries := make([]ctgo.LeafEntry, 0)
			gap := treeSize - lastTreeSize

			for int64(len(entries)) < gap {
				currentEntries, err := getEntries(log, lastTreeSize+int64(len(entries)), treeSize)
				if err != nil {
					fmt.Printf("Failed to get entries @ %s: %s\n", log, err.Error())
					break
				} else {
					entries = append(entries, currentEntries...)
				}
			}

			fmt.Println("Found", len(entries), "of", gap, "entries")

			for i, entry := range entries {
				rle, err := ctgo.RawLogEntryFromLeaf(int64(i)+lastTreeSize, &entry)
				if err != nil {
					fmt.Println("Failed to decode entry", err.Error())
					continue
				}
				cert, err := x509.ParseCertificate(rle.Cert.Data)
				if err != nil {
					fmt.Println("Failed to parse certificate", err.Error())
					continue
				}

				triggered := false
				for _, query := range TargetDefinition.Queries {
					query = strings.ToLower(query)
					for _, name := range cert.DNSNames {
						if strings.Contains(strings.ToLower(name), query) {
							triggered = true
							break
						}
					}
					if strings.Contains(strings.ToLower(cert.Subject.String()), query) {
						triggered = true
						break
					}
				}
				if triggered {
					message := fmt.Sprintf("Issuer: %s\nSubject: %s\nAlgorithm: %s\nSHA-1: %X\nSHA-256: %X\nSerial: %X\nValid after: %s\nValid until: %s\n",
						cert.Issuer.String(),
						cert.Subject.String(),
						cert.PublicKeyAlgorithm.String(),
						sha1.Sum(cert.Raw),
						sha256.Sum256(cert.Raw),
						cert.SerialNumber,
						cert.NotBefore.String(),
						cert.NotAfter.String(),
					)
					fmt.Println(strings.Join(cert.DNSNames, ", "), message)

					MessageQueue <- Message{
						Title:   "Certificate issued to: " + strings.Join(cert.DNSNames, ", "),
						Message: message,
					}
				}
			}

			lastTreeSizes[log] = treeSize
		}
		TargetDefinition.Mutex.Unlock()
		time.Sleep(CT_FETCH_INTERVAL)
	}
}

func awaitMessages() {
	for message := range MessageQueue {
		encoded, err := json.Marshal(struct {
			Token   string `json:"token"`
			User    string `json:"user"`
			Message string `json:"message"`
			Title   string `json:"title"`
		}{
			Token:   PushoverApiKey,
			User:    PushoverUserKey,
			Message: message.Message,
			Title:   message.Title,
		})
		if err != nil {
			fmt.Println("Failed to push message: ", err.Error())
			return
		}
		req, err := http.NewRequest(http.MethodPost, "https://api.pushover.net/1/messages.json", bytes.NewBuffer(encoded))
		req.Header.Add("content-type", "application/json")
		req.Header.Add("user-agent", "github.com/janic0/CertificateTransparencyAlerter")
		if err != nil {
			fmt.Println("Failed to perform http request: ", err.Error())
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println("Failed to send http request: ", err.Error())
			return
		}
		if resp.StatusCode != 200 {
			fmt.Println("Message sending failed to send with status code: ", resp.StatusCode)
			return
		}
	}

}

func main() {
	go runLoop()
	go awaitMessages()
	for {
		content, err := os.ReadFile("config.yml")
		if err != nil {
			fmt.Println("Failed to read config file (config.yml):", err.Error())
			time.Sleep(CONFIG_LOAD_INTERVAL)
			continue
		}
		config := &ConfigFormat{}
		err = yaml.Unmarshal(content, config)
		if err != nil {
			fmt.Println("Error in config file (config.yml):", err.Error())
			time.Sleep(CONFIG_LOAD_INTERVAL)
			continue
		}
		TargetDefinition.Mutex.Lock()
		TargetDefinition.Logs = config.Logs
		TargetDefinition.Queries = config.Queries
		TargetDefinition.Mutex.Unlock()
		time.Sleep(CONFIG_LOAD_INTERVAL)
	}
}
