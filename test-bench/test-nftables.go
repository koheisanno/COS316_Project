package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	// Define the IP address you want to test
	ipToTest := "146.190.33.175"

	// Add the IP address to the blacklist using nftables
	cmdAdd := exec.Command("nft", "add", "rule", "ip", "filter", "input", "ip", "saddr", ipToTest, "drop")
	cmdAdd.Stdout = os.Stdout
	cmdAdd.Stderr = os.Stderr
	if err := cmdAdd.Run(); err != nil {
		fmt.Println("Error adding IP to blacklist:", err)
		return
	}

	// Measure the time it takes to drop a packet
	startTime := time.Now()

	// Simulate incoming packet with the blacklisted IP (replace with your actual test)

	// Here, we are using the "ping" command to simulate an incoming packet.
	cmd := exec.Command("ping", "-c", "1", ipToTest)
	// pipe the Stdout of the previous command to Stdout of system
	cmd.Stdout = os.Stdout
	// pipe the Stderr of the previous command to the Stderr of system
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("Error simulating packet:", err)
		return
	}

	// Calculate the time taken
	elapsedTime := time.Since(startTime)

	// Remove the IP address from the blacklist
	cmdRemove := exec.Command("nft", "delete", "rule", "ip", "filter", "input", "ip", "saddr", ipToTest, "drop")
	cmdRemove.Stdout = os.Stdout
	cmdRemove.Stderr = os.Stderr
	if err := cmdRemove.Run(); err != nil {
		fmt.Println("Error removing IP from blacklist:", err)
		return
	}

	// Print the time taken to drop the packet
	fmt.Printf("Time taken to drop packet with IP %s: %s\n", ipToTest, elapsedTime)
}

