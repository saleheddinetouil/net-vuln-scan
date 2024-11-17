# Network Port Mapper and Threat Identifier

This Go script performs network port scanning and identifies potential security threats based on open ports and services. It uses the `nmap` library for efficient scanning and includes a threat database for vulnerability assessment.

## Features

* **Port Scanning:** Scans a target host for open ports using the `nmap` library.
* **Service Detection:** Identifies the services running on open ports.
* **Version Detection:** Retrieves version information for running services.
* **Threat Identification:** Compares open ports and services against a threat database to identify potential vulnerabilities.
* **Customizable Port Range:** Allows specifying the ports to scan.
* **Clear Output:** Presents scan results and identified threats in a readable format.


## Requirements

* **Go:** Make sure you have Go installed on your system.
* **Nmap library:** `go get github.com/Ullaakut/nmap/v3`
* **Nmap:** The `nmap` command-line tool must be installed and accessible in your system's PATH.  (On Linux/macOS: `sudo apt-get install nmap` or `brew install nmap`)


## Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/network-port-mapper.git  (Replace with your repo URL)
   cd network-port-mapper
   ```

2. **Run the script:**
   ```bash
   go run main.go <target_host> <ports>
   ```

   * `<target_host>`: The IP address or hostname of the target to scan.
   * `<ports>`: A comma-separated list of ports or port ranges to scan (e.g., `22,80,443,8080-8085`).

   Example:
   ```bash
   go run main.go 192.168.1.100 22,80,443,3389
   ```
   or
   ```bash
   go run main.go scanme.nmap.org 21-25,80,443  # Example using a public test server.
   ```

## Threat Database

The `ThreatDB` variable in `main.go` contains a list of known threats. You should expand this database with more vulnerabilities as needed. The format is:

```go
type Threat struct {
    Port     int
    Service  string
    Severity string // e.g., "Low", "Medium", "High"
    Description string
}
```


## Security Considerations

* **Permission:** Always obtain proper authorization before scanning any network or system. Unauthorized port scanning can be illegal and unethical.
* **Network Impact:**  Be mindful of the potential impact of scanning on the target network.  Avoid aggressive timing options on production networks.
* **False Positives:** The threat database is not exhaustive, and the script may report false positives.  Always verify any identified threats before taking action.




## Contributing

Contributions are welcome!  Please feel free to open issues or submit pull requests.


## License

This project is licensed under the [MIT License](LICENSE).  (Create a LICENSE file with the MIT license text).

