# UBX Protocol High Level Analyzer

A High Level Analyzer (HLA) for Saleae Logic 2 that decodes u-blox UBX protocol messages.

See [the UBX protocol specification](https://content.u-blox.com/sites/default/files/documents/u-blox-F9-HPS-1.30_InterfaceDescription_UBX-22010984.pdf) for more details.

## Features

- Decodes all standard UBX protocol message classes:
  - NAV (Navigation Results): PVT, SAT, STATUS, POSECEF, POSLLH, DOP, VELECEF, VELNED, CLOCK, TIMEGPS, TIMEUTC, ODO, AOPSTATUS
  - RXM (Receiver Manager): RAW, RAWX, SFRBX
  - INF (Information): Debug, Error, Notice, Test, Warning
  - ACK (Acknowledgements): ACK, NAK
  - CFG (Configuration): PRT, MSG, RATE, NAV5, GNSS, ANT, PM, RINV, ITFM, LOGFILTER, TMODE, SBAS, USB
  - MON (Monitoring): IO, VER, MSGPP, RXBUF, TXBUF, HW, HW2
  - TIM (Timing): SVIN, VRFY, DOSC, TOS, SMEAS
  - LOG (Logging): ERASE, STRING, CREATE, INFO, RETRIEVE

- Provides detailed parsing of message fields including:
  - GPS fix information
  - Satellite tracking data
  - Position and velocity data
  - Timing information
  - Hardware status
  - Buffer statistics
  - Version information
  - Configuration settings

## Installation

1. Download the extension files
2. In Logic 2, click "Load Existing Extension"
3. Navigate to and select the downloaded extension folder

## Usage

1. Capture serial data from your u-blox GPS receiver
2. Add the "UBX Protocol" analyzer to your capture
3. Configure the analyzer settings if needed
4. The analyzer will automatically decode UBX messages and display:
   - Message class and ID
   - Message length
   - Parsed message contents
   - Checksum validation

## Message Display Format

Messages are displayed in the following format:
```
UBX: [Class]-[ID]: [Details]
```

Examples:
- `UBX: NAV-PVT: Time: 2023-01-01 12:00:00, Fix: 3D Fix, Sats: 8, Pos: 37.123456°, -122.123456°, Alt: 100.5m`
- `UBX: MON-VER: SW=ROM CORE 3.01 (107888) HW=00080000`
- `UBX: CFG-RATE: Measurement Rate: 1000ms, Navigation Rate: 1 cycles, Time Reference: GPS`

## Error Handling

The analyzer performs checksum validation and displays error messages for:
- Invalid checksums
- Incomplete messages
- Invalid message formats

## Supported u-blox Devices

This HLA supports UBX protocol messages from u-blox GPS/GNSS receivers including:
- NEO series
- LEA series
- ZED series
- MAX series
- And other u-blox receivers using the UBX protocol

## Technical Details

- Synchronization: Detects UBX message start (0xB5 0x62)
- Message Structure: Class, ID, Length, Payload, Checksum
- Checksum: Fletcher algorithm (2 bytes)
- Endianness: Little-endian for multi-byte fields

## Limitations

- Maximum message length: 65535 bytes
- Does not decode proprietary message types
- NMEA and RTCM protocols are not supported
