package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v3" // Use a well-maintained nmap library
)

// PortMapping represents a port mapping.
type PortMapping struct {
	Protocol string
	Port     int
	Service  string
	State    string
	Version  string // Version information if available
}

// Threat represents a potential threat associated with a port or service.
type Threat struct {
	Port     int
	Service  string
	Severity string // e.g., "Low", "Medium", "High"
	Description string
}

// ThreatDB (you would typically load this from a file or database)
var ThreatDB = []Threat{
    {Port: 22, Service: "ssh", Severity: "Medium", Description: "SSH is susceptible to brute-force attacks if not properly secured."},
    {Port: 23, Service: "telnet", Severity: "High", Description: "Telnet transmits data in cleartext, posing a serious security risk."},
    {Port: 80, Service: "http", Severity: "Medium", Description: "HTTP is vulnerable to various web attacks if not properly configured."},
    {Port: 443, Service: "https", Severity: "Low", Description: "HTTPS is generally secure but can be vulnerable if using outdated SSL/TLS versions."},
    {Port: 3389, Service: "rdp", Severity: "High", Description: "RDP is a common target for ransomware attacks."},
    // ... add more threats as needed
}



func scanPorts(target string, ports string) ([]PortMapping, error) {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPorts(ports), // Specify ports or ranges
		nmap.WithServiceInfo(), // Enable service version detection
		// Add other nmap options as needed (e.g., timing, OS detection)
		nmap.WithTimingTemplate(nmap.TimingAggressive), // Faster, but potentially less accurate
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %w", err)
	}

	var portMappings []PortMapping

	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			portMappings = append(portMappings, PortMapping{
				Protocol: port.Protocol,
				Port:     int(port.Number),
				Service:  port.Service.Name,
				State:    port.State.State,
                Version:  port.Service.Version, 
			})
		}
	}

	return portMappings, nil
}

func identifyThreats(portMappings []PortMapping) []Threat {
	var identifiedThreats []Threat
	for _, pm := range portMappings {
		for _, threat := range ThreatDB {
			if pm.Port == threat.Port && pm.Service == threat.Service {
				identifiedThreats = append(identifiedThreats, threat)
			}
		}
	}
	return identifiedThreats
}


func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go <target_host> <ports>")
		return
	}

	target := os.Args[1]
	ports := os.Args[2]



	portMappings, err := scanPorts(target, ports)
	if err != nil {
		fmt.Println("Error scanning ports:", err)
		return
	}

	fmt.Println("Port Mappings:")
	for _, pm := range portMappings {
		fmt.Printf("Protocol: %s, Port: %d, Service: %s, State: %s, Version: %s\n",
			pm.Protocol, pm.Port, pm.Service, pm.State, pm.Version)
	}

	threats := identifyThreats(portMappings)
	if len(threats) > 0 {
		fmt.Println("\nIdentified Threats:")
		for _, threat := range threats {
			fmt.Printf("Port: %d, Service: %s, Severity: %s, Description: %s\n",
				threat.Port, threat.Service, threat.Severity, threat.Description)
		}
	} else {
		fmt.Println("\nNo threats identified.")
	}
} 
