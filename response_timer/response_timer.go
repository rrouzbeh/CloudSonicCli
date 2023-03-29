package response_timer

import (
	"sort"

	"github.com/rrouzbeh/CloudSonicCli/connector"
)

// GetTopLowestResponseTimes returns the top N lowest response times from a slice of IPResponseTime structs.
func GetTopLowestResponseTimes(responseTimes []connector.IPResponseTime, n int) []connector.IPResponseTime {
	// Sort the response times in ascending order
	sort.Slice(responseTimes, func(i, j int) bool {
		return responseTimes[i].ResponseTime < responseTimes[j].ResponseTime
	})

	// If there are fewer response times than requested, return them all
	if len(responseTimes) < n {
		return responseTimes
	}

	// Return the top N lowest response times
	return responseTimes[:n]
}
