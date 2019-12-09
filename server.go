package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	//base         = "http://localhost:8082"
	base         = "https://ji.luupi.net"
	audit        = "/652/audit"
	clock        = "/652/clock"
	access       = "/652/access"
	secret       = "galumphing"
	timeoutInSec = time.Duration(3) * time.Second
	charset      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	defaultPort  = "9090"
)

var (
	seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
)

type INinRandom interface {
	getRandomString(length int) string
}
type INinHttpClient interface {
	getResponse(url string, payload map[string]interface{}) (string, error)
}
type INinCredential interface {
	getNonce(nRandom NinRandom) string
	getSignature(url, act, nonce string) string
}
type INinTimeProxy interface {
	begin(done chan bool)
	end() (string, error)
	clock() error
	HandleServerTime() (string, error)
}
type INinAuditLogProxy interface {
	getAuditBase() (int, error)
	getAuditLog(offsetCount int) ([]string, error)
	resetAuditLog(offsetCount int)
	HandleAuditLogs() ([]string, error)
}

/**
*	Helper for
*	Generate random string of given length
 */

var _ = INinRandom(&NinRandom{})

type NinRandom struct {
}

func (n NinRandom) getRandomString(length int) string {
	b := make([]byte, length)
	len := len(charset)
	for i := range b {
		b[i] = charset[seededRand.Intn(len)]
	}
	return string(b)
}
func GetNineRandom() NinRandom {
	return NinRandom{}
}

//----------Ends NinRandom---------------

/**
*	Helper for
* 	Client that handle http calls. Current timeout is 3 seconds and is hardcoded
**/

var _ = INinHttpClient(&NinHttpClient{})

type NinHttpClient struct {
	timeout time.Duration
}

func (n NinHttpClient) getResponse(url string, payload map[string]interface{}) (string, error) {
	httpClient := http.Client{
		Timeout: n.timeout,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
func GetNinHttpClient() NinHttpClient {
	return NinHttpClient{
		timeout: timeoutInSec,
	}
}

//----------Ends NinHttpClient---------------

/**
*	Helper for
* 	Client that will handle generating new signature for each request
**/

type NinCredential struct {
}

var _ = INinCredential(&NinCredential{})

func (n NinCredential) getNonce(nRandom NinRandom) string {
	return nRandom.getRandomString(18)
}
func (n NinCredential) getSignature(url, act, nonce string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\r\n%s\r\n%s\r\n%s", url, act, nonce, secret)
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return sig
}
func GetNinCredential() NinCredential {
	return NinCredential{}
}

//----------Ends NinCredential---------------

/**
*	Helper for
* 	Client that will handle fetching server-time from endpoint
**/

var _ = INinTimeProxy(&NinTimeProxy{})

type NinTimeProxy struct {
	NinRandom
	NinHttpClient
	NinCredential
}

func (n NinTimeProxy) begin(done chan bool) {
	nonce := n.getNonce(n.NinRandom)
	act := "begin"
	url := access

	payload := map[string]interface{}{
		"Nonce":     nonce,
		"Act":       act,
		"Timeout":   250000,
		"Signature": n.getSignature(url, act, nonce),
	}
	n.getResponse(base+url, payload)
	done <- true
}

func (n NinTimeProxy) end() (string, error) {
	nonce := n.getNonce(n.NinRandom)
	act := "end"
	url := access

	payload := map[string]interface{}{
		"Nonce":     nonce,
		"Act":       act,
		"Timeout":   250000,
		"Signature": n.getSignature(url, act, nonce),
	}
	serverTime, err := n.getResponse(base+url, payload)
	return strings.Trim(serverTime,"\n"), err
}
func (n NinTimeProxy) clock() error {
	nonce := n.getNonce(n.NinRandom)
	act := "observe"
	url := clock

	payload := map[string]interface{}{
		"Nonce":     nonce,
		"Act":       act,
		"Timeout":   0,
		"Signature": n.getSignature(url, act, nonce),
	}
	_, err := n.getResponse(base+url, payload)
	return err
}

func (n NinTimeProxy) HandleServerTime() (string, error) {
	timerTask := time.NewTicker(time.Duration(5) * time.Microsecond)
	defer timerTask.Stop()
	done := make(chan bool, 1)
	go n.begin(done)

	// warm up handler
	func() {
		for {
			select {
			case <-done:
				return
			case <-timerTask.C:
				if err := n.clock(); err != nil {
					fmt.Println(err.Error())
				}
			}
		}
	}()
	return n.end()
}
func GetNinTimeProxy(
	nRandom NinRandom,
	nHttpClient NinHttpClient,
	nCredential NinCredential) NinTimeProxy {
	return NinTimeProxy{
		NinRandom:     nRandom,
		NinHttpClient: nHttpClient,
		NinCredential: nCredential,
	}
}

//----------Ends NinTimeProxy---------------

/**
*	Helper for
* 	Client that will handle audit log from endpoint
**/

var _ = INinAuditLogProxy(&NinAuditLogProxy{})

type NinAuditLogProxy struct {
	NinRandom
	NinHttpClient
	NinCredential
}

func (n NinAuditLogProxy) getAuditBase() (int, error) {
	nonce := n.getNonce(n.NinRandom)
	act := ""
	url := audit

	payload := map[string]interface{}{
		"Nonce":     nonce,
		"Act":       act,
		"Offset":    0,
		"Signature": n.getSignature(url, act, nonce),
	}
	base, err := n.getResponse(base+audit, payload)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(base))
}

func (n NinAuditLogProxy) getAuditLog(offsetCount int) ([]string, error) {
	nonce := n.getNonce(n.NinRandom)
	act := "burble"
	url := audit

	payload := map[string]interface{}{
		"Nonce":     nonce,
		"Act":       act,
		"Offset":    offsetCount,
		"Signature": n.getSignature(url, act, nonce),
	}
	logsAsString, err := n.getResponse(base+audit, payload)
	if err != nil {
		return []string{}, err
	}
	return strings.Split(logsAsString, "\n"), nil
}

func (n NinAuditLogProxy) resetAuditLog(offsetCount int) {
	nonce := n.getNonce(n.NinRandom)
	act := "chortle"
	url := audit
	if offsetCount < 0 {
		offsetCount = 0
	}
	payload := map[string]interface{}{
		"Nonce":     nonce,
		"Act":       act,
		"Offset":    offsetCount,
		"Signature": n.getSignature(url, act, nonce),
	}
	_, err := n.getResponse(base+audit, payload)
	if err != nil {
		fmt.Println("->", err)
	}
}

func (n NinAuditLogProxy) HandleAuditLogs() ([]string, error) {
	baseOffset, _ := n.getAuditBase()
	auditLogs, _ := n.getAuditLog(baseOffset)
	n.resetAuditLog(len(auditLogs) + baseOffset - 1)
	return auditLogs, nil
}
func GetNinAuditLogProxy(
	nRandom NinRandom,
	nHttpClient NinHttpClient,
	nCredential NinCredential) NinAuditLogProxy {
	return NinAuditLogProxy{
		NinRandom:     nRandom,
		NinHttpClient: nHttpClient,
		NinCredential: nCredential,
	}
}

//----------Ends NinAuditLogProxy---------------

func main() {
	nRandom := GetNineRandom()
	nHttpClient := GetNinHttpClient()
	nCredentials := GetNinCredential()

	nTimeProxy := GetNinTimeProxy(nRandom, nHttpClient, nCredentials)
	nLogProxy := GetNinAuditLogProxy(nRandom, nHttpClient, nCredentials)

	serverPort := os.Getenv("PORT")
	if serverPort == "" {
		serverPort = defaultPort
	}
	http.HandleFunc("/nin/info", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Max-Age", "3600")
		writer.Header().Set("Content-Type", "application/json")
		serverTime, _ := nTimeProxy.HandleServerTime()
		auditLogs, _ := nLogProxy.HandleAuditLogs()
		response, _ := json.Marshal(map[string]interface{}{
			"timeInSec": serverTime,
			"auditLogs":   auditLogs,
		})
		writer.WriteHeader(http.StatusOK)
		writer.Write(response)
	})
	fmt.Println("server will run at ", fmt.Sprintf(":%s", serverPort))
	err := http.ListenAndServe(fmt.Sprintf(":%s", serverPort), nil)
	if err != nil {
		log.Fatal(err)
	}
}
