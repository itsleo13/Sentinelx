# SentinelX - TCP Port Scanner

SentinelX is a Python-based TCP Port Scanner that scans a target IP address or domain to identify open TCP ports and their associated services.

## Features

- TCP Port Scanning
- Service Detection
- Colored Terminal Output
- Scan Summary
- Save Scan Report
- Simple CLI Interface

## Technologies Used

- Python
- Socket Programming
- Colorama
- TQDM

## Project Structure

```
PortScanner/
│── scanner.py
│── banner.py
│── services.py
│── file_handler.py
│── utils.py
│── requirements.txt
│── README.md
│── results/
```

## Installation

Clone the repository

```bash
git clone https://github.com/itsleo13/Sentinelx.git
```

Go to the project directory

```bash
cd PortScanner
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the scanner

```bash
python scanner.py
```

## Example

```
Enter Target IP or Domain: scanme.nmap.org
Enter Start Port: 20
Enter End Port: 100
```

Output

```
Port 22   OPEN   ssh
Port 80   OPEN   http
```

## Future Improvements

- Banner Grabbing
- Multi-threaded Scanning
- GUI Version
- PDF Report Generation
- AI-based Security Recommendations

## Author

**Leo**