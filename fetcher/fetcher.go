package fetcher

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// FetchIPs retrieves IP addresses from the specified URL and returns them as a slice of strings.
func FetchIPs() ([]string, error) {
	url := "https://raw.githubusercontent.com/rrouzbeh/CloudSonic/main/ip.txt"

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching IP addresses: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	ipList := strings.Split(string(body), "\n")

	// Remove empty elements, if any
	var cleanedIPList []string
	for _, ip := range ipList {
		if ip != "" {
			// replace the last octet with a random number between 1 and 254
			cleanedIPList = append(cleanedIPList, ip)
		}
	}

	return cleanedIPList, nil
}
