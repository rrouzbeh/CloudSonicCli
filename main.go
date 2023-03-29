package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cheggaaa/pb/v3"

	"github.com/rrouzbeh/CloudSonicCli/connector"
	"github.com/rrouzbeh/CloudSonicCli/fetcher"
	"github.com/rrouzbeh/CloudSonicCli/response_timer"
)

func main() {
	// Set up a signal handler for interruption signals (e.g., Ctrl+C)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	totalIterations := 20
	progressBar := pb.StartNew(totalIterations)
	go func() {
		ipList, _ := fetcher.FetchIPs()
		responseTimes, err := connector.ConnectAndGetResponseTimes(ipList, progressBar, totalIterations)
		if err != nil {
			fmt.Println(err)
			return
		}
		progressBar.Finish()
		top10 := response_timer.GetTopLowestResponseTimes(responseTimes, 10)

		for i, result := range top10 {
			fmt.Printf("%d. IP: %s, Response Time: %v \n", i+1, result.IP, result.ResponseTime)
		}
	}()

	// Wait for an interruption signal
	<-signalChan
	fmt.Println("\nReceived an interrupt, exiting...")
}
