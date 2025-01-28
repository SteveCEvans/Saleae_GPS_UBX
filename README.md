§# UBX Protocol Analyzer

This High Level Analyzer (HLA) for Saleae Logic 2 decodes the u-blox UBX protocol messages. The UBX protocol is a binary protocol used by u-blox GNSS receivers for configuration and data retrieval.

## Protocol Overview

The UBX protocol uses the following message structure:

```
+----------+---------+---------+--------+------------+---------+
| Sync     | Class   | ID      | Length | Payload    | Checksum|
| 2 bytes  | 1 byte  | 1 byte  | 2 bytes| N bytes    | 2 bytes |
+----------+---------+---------+--------+------------+---------+
```

- Sync: 0xB5 0x62
- Class: Message class (e.g., NAV, CFG, MON)
- ID: Message ID within the class
- Length: Payload length (little-endian)
- Payload: Message-specific data
- Checksum: Fletcher checksum over Class, ID, Length, and Payload

## Usage

1. Install this analyzer in Logic 2
2. Add a new analyzer to your capture
3. Select "UBX Protocol" from the list of analyzers
4. The analyzer requires an existing async serial analyzer as its input
5. Configure the async serial analyzer for your data:
   - Typically 9600, 38400, or 115200 baud
   - 8 data bits
   - 1 stop bit
   - No parity

## Supported Message Classes

- NAV (0x01): Navigation Results
- RXM (0x02): Receiver Manager Messages
- INF (0x04): Information Messages
- ACK (0x05): Acknowledge/Nack Messages
- CFG (0x06): Configuration Messages
- UPD (0x09): Firmware Update Messages
- MON (0x0A): Monitoring Messages
- TIM (0x0D): Timing Messages
- MGA (0x13): Multiple GNSS Assistance
- LOG (0x21): Logging Messages
- SEC (0x27): Security Messages
- HNR (0x28): High Rate Navigation Results

## Output Format

The analyzer outputs frames in the following format:
- Valid messages: `UBX: <class>-0x<id> (<length> bytes)`
- Invalid messages: `UBX Error: Checksum mismatch` 