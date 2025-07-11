# dnssniffer: cli sniffer for dns
DNS Sniffer is a tool for intercepting and analyzing DNS traffic, written in the Go language. The program allows you to capture DNS packets in real time and display their contents in the terminal.

# Features
- Interception of DNS queries and responses
- Support for working with a specific network interface
- Listing available network interfaces
- Reading and interpreting the main fields of DNS packets:
    - Transaction ID

    - Packet type (Query/Response)

    - Flags (AA, TC, RD, RA, Z)

    - Operation codes (Opcode, RCode)

    - Number of records (Questions, Answers, Authorities, Additionals)

    - Detailed information about questions


## Build
```bash
git clone https://github.com/crewcrew23/dnssniffer
cd dnssniffer
make
```


##  Usage
```bash
./bin/dnssniffer --list #display list of your network interfaces
./bin/dnssniffer -i <name of interface>
```

## Command line options

| Flag         | Args       | Desc                                                                 |
|--------------|----------------|--------------------------------------------------------------------------|
| `-i`         | `<network interface>`  | Specifies the network interface      |
| `--list` |              | Lists available network interfaces.   |

