# UBX Protocol Constants

# Sync characters that mark the start of a UBX message
SYNC1 = 0xB5  # First sync character 'µ'
SYNC2 = 0x62  # Second sync character 'b'

# Message Classes
CLASS_NAV = 0x01  # Navigation Results: Position, Speed, Time, Acc, Heading, DOP, SVs used
CLASS_RXM = 0x02  # Receiver Manager Messages: Satellite Status, RTCM data
CLASS_INF = 0x04  # Information Messages: Printf-Style Messages, Debug etc.
CLASS_ACK = 0x05  # Acknowledge/Nack Messages: Response to CFG messages
CLASS_CFG = 0x06  # Configuration Messages: Set/Get device configurations
CLASS_UPD = 0x09  # Firmware Update Messages: Memory/Flash updates
CLASS_MON = 0x0A  # Monitoring Messages: Communication Status, CPU Load, Stack Usage, Task Status
CLASS_TIM = 0x0D  # Timing Messages: Time Pulse Output, Time Mark Results
CLASS_MGA = 0x13  # Multiple GNSS Assistance Messages: Assistance data for various GNSS
CLASS_LOG = 0x21  # Logging Messages: Log creation, deletion, info and retrieval
CLASS_SEC = 0x27  # Security Feature Messages
CLASS_HNR = 0x28  # High Rate Navigation Results Messages

# NAV Message IDs
NAV_PVT = 0x07      # Navigation Position Velocity Time Solution
NAV_STATUS = 0x03   # Receiver Navigation Status
NAV_DOP = 0x04      # Dilution of Precision
NAV_ATT = 0x05      # Attitude Solution
NAV_POSECEF = 0x01  # Position Solution in ECEF
NAV_POSLLH = 0x02   # Geodetic Position Solution
NAV_ODO = 0x09      # Odometer Solution
NAV_VELECEF = 0x11  # Velocity Solution in ECEF
NAV_VELNED = 0x12   # Velocity Solution in NED
NAV_TIMEGPS = 0x20  # GPS Time Solution
NAV_TIMEUTC = 0x21  # UTC Time Solution
NAV_CLOCK = 0x22    # Clock Solution
NAV_SAT = 0x35      # Satellite Information
NAV_AOPSTATUS = 0x60  # AssistNow Autonomous Status

# CFG Message IDs
CFG_PRT = 0x00    # Port Configuration
CFG_MSG = 0x01    # Message Configuration
CFG_RATE = 0x08   # Navigation/Measurement Rate Settings
CFG_ANT = 0x13    # Antenna Control Settings
CFG_SBAS = 0x16   # SBAS Configuration
CFG_TMODE = 0x1D  # Time Mode Settings
CFG_NAV5 = 0x24   # Navigation Engine Settings
CFG_PM = 0x32     # Power Management Configuration
CFG_RINV = 0x34   # Remote Inventory
CFG_ITFM = 0x39   # Jamming/Interference Monitor Configuration
CFG_GNSS = 0x3E   # GNSS System Configuration
CFG_LOGFILTER = 0x47  # Data Logger Configuration
CFG_USB = 0x86    # USB Configuration

# MON Message IDs
MON_VER = 0x04    # Receiver/Software Version
MON_HW = 0x09     # Hardware Status
MON_IO = 0x02     # I/O Subsystem Status
MON_MSGPP = 0x06  # Message Parse and Process Status
MON_RXBUF = 0x07  # Receiver Buffer Status
MON_TXBUF = 0x08  # Transmitter Buffer Status
MON_HW2 = 0x0B    # Extended Hardware Status

# TIM Message IDs
TIM_TP = 0x01     # Time Pulse Timedata
TIM_TM2 = 0x03    # Time Mark Data
TIM_SVIN = 0x04   # Survey-In Data
TIM_VRFY = 0x06   # Sourced Time Verification
TIM_DOSC = 0x11   # Disciplined Oscillator Control
TIM_TOS = 0x12    # Time Pulse Time and Frequency Data
TIM_SMEAS = 0x13  # Source Measurement

# LOG Message IDs
LOG_CREATE = 0x07    # Create Log File
LOG_ERASE = 0x03    # Erase Logged Data
LOG_STRING = 0x04    # Store String into Log
LOG_INFO = 0x08     # Log Information
LOG_RETRIEVE = 0x09  # Request Log Data

# ACK Message IDs
ACK_ACK = 0x01  # Message Acknowledged
ACK_NAK = 0x00  # Message Not-Acknowledged

# Dynamic Platform Models for CFG-NAV5
PLATFORM_PORTABLE = 0      # Portable
PLATFORM_STATIONARY = 2    # Stationary
PLATFORM_PEDESTRIAN = 3    # Pedestrian
PLATFORM_AUTOMOTIVE = 4    # Automotive
PLATFORM_SEA = 5          # Sea
PLATFORM_AIRBORNE_1G = 6   # Airborne with <1g Acceleration
PLATFORM_AIRBORNE_2G = 7   # Airborne with <2g Acceleration
PLATFORM_AIRBORNE_4G = 8   # Airborne with <4g Acceleration
PLATFORM_WRIST_WORN = 9    # Wrist-worn watch

# Fix Types
FIX_NONE = 0              # No Fix
FIX_DEAD_RECKONING = 1    # Dead Reckoning only
FIX_2D = 2               # 2D Fix
FIX_3D = 3               # 3D Fix
FIX_GPS_DEAD_RECKONING = 4  # GPS + Dead Reckoning
FIX_TIME_ONLY = 5         # Time only fix

# GNSS Types
GNSS_GPS = 0      # GPS
GNSS_SBAS = 1     # SBAS
GNSS_GALILEO = 2  # Galileo
GNSS_BEIDOU = 3   # BeiDou
GNSS_IMES = 4     # IMES
GNSS_QZSS = 5     # QZSS
GNSS_GLONASS = 6  # GLONASS

# Time Reference Sources
TIME_REF_UTC = 0      # UTC Time
TIME_REF_GPS = 1      # GPS Time
TIME_REF_GLONASS = 2  # GLONASS Time
TIME_REF_BEIDOU = 3   # BeiDou Time
TIME_REF_GALILEO = 4  # Galileo Time

# Payload Offsets - Common Fields
OFFSET_CLASS = 0
OFFSET_ID = 1
OFFSET_LENGTH = 2  # 2 bytes, little-endian

# Payload Offsets - NAV-PVT
OFFSET_PVT_ITOW = 0    # GPS time of week (ms)
OFFSET_PVT_YEAR = 4    # Year (UTC)
OFFSET_PVT_MONTH = 6   # Month (UTC)
OFFSET_PVT_DAY = 7     # Day of month (UTC)
OFFSET_PVT_HOUR = 8    # Hour (UTC)
OFFSET_PVT_MIN = 9     # Minute (UTC)
OFFSET_PVT_SEC = 10    # Second (UTC)
OFFSET_PVT_VALID = 11  # Validity flags
OFFSET_PVT_FIX = 20    # Fix type
OFFSET_PVT_FLAGS = 21  # Fix status flags
OFFSET_PVT_NUMSV = 23  # Number of satellites used
OFFSET_PVT_LON = 24    # Longitude (deg * 1e-7)
OFFSET_PVT_LAT = 28    # Latitude (deg * 1e-7)
OFFSET_PVT_HEIGHT = 32 # Height above ellipsoid (mm)
OFFSET_PVT_HMSL = 36   # Height above mean sea level (mm)

# Payload Offsets - MON-VER
OFFSET_VER_SW = 0     # Software version string (30 bytes)
OFFSET_VER_HW = 30    # Hardware version string (10 bytes)
OFFSET_VER_EXT = 40   # Extension string start (N * 30 bytes)
VER_STRING_LENGTH = 30  # Length of version strings

# Common Field Sizes
SIZE_U1 = 1   # Unsigned char (1 byte)
SIZE_U2 = 2   # Unsigned short (2 bytes)
SIZE_U4 = 4   # Unsigned int (4 bytes)
SIZE_I1 = 1   # Signed char (1 byte)
SIZE_I2 = 2   # Signed short (2 bytes)
SIZE_I4 = 4   # Signed int (4 bytes)
SIZE_X1 = 1   # Bitfield (1 byte)
SIZE_X2 = 2   # Bitfield (2 bytes)
SIZE_X4 = 4   # Bitfield (4 bytes)

# NAV-STATUS Offsets
OFFSET_STATUS_ITOW = 0      # GPS time of week (ms)
OFFSET_STATUS_GPSFIX = 4    # GPSfix Type
OFFSET_STATUS_FLAGS = 5     # Navigation Status Flags
OFFSET_STATUS_FIXSTAT = 6   # Fix Status Information
OFFSET_STATUS_FLAGS2 = 7    # Additional Navigation Output Status
OFFSET_STATUS_TTFF = 8      # Time to first fix (ms)
OFFSET_STATUS_MSSS = 12     # Milliseconds since startup/reset

# NAV-POSECEF Offsets
OFFSET_POSECEF_ITOW = 0    # GPS time of week (ms)
OFFSET_POSECEF_ECEFX = 4   # ECEF X coordinate (cm)
OFFSET_POSECEF_ECEFY = 8   # ECEF Y coordinate (cm)
OFFSET_POSECEF_ECEFZ = 12  # ECEF Z coordinate (cm)
OFFSET_POSECEF_PACC = 16   # Position Accuracy Estimate (cm)

# NAV-POSLLH Offsets
OFFSET_POSLLH_ITOW = 0     # GPS time of week (ms)
OFFSET_POSLLH_LON = 4      # Longitude (deg * 1e-7)
OFFSET_POSLLH_LAT = 8      # Latitude (deg * 1e-7)
OFFSET_POSLLH_HEIGHT = 12  # Height above ellipsoid (mm)
OFFSET_POSLLH_HMSL = 16    # Height above mean sea level (mm)
OFFSET_POSLLH_HACC = 20    # Horizontal Accuracy Estimate (mm)
OFFSET_POSLLH_VACC = 24    # Vertical Accuracy Estimate (mm)

# NAV-DOP Offsets
OFFSET_DOP_ITOW = 0     # GPS time of week (ms)
OFFSET_DOP_GDOP = 4     # Geometric DOP * 0.01
OFFSET_DOP_PDOP = 6     # Position DOP * 0.01
OFFSET_DOP_TDOP = 8     # Time DOP * 0.01
OFFSET_DOP_VDOP = 10    # Vertical DOP * 0.01
OFFSET_DOP_HDOP = 12    # Horizontal DOP * 0.01
OFFSET_DOP_NDOP = 14    # Northing DOP * 0.01
OFFSET_DOP_EDOP = 16    # Easting DOP * 0.01

# NAV-VELECEF Offsets
OFFSET_VELECEF_ITOW = 0    # GPS time of week (ms)
OFFSET_VELECEF_ECEFVX = 4  # ECEF X velocity (cm/s)
OFFSET_VELECEF_ECEFVY = 8  # ECEF Y velocity (cm/s)
OFFSET_VELECEF_ECEFVZ = 12 # ECEF Z velocity (cm/s)
OFFSET_VELECEF_SACC = 16   # Speed Accuracy Estimate (cm/s)

# NAV-VELNED Offsets
OFFSET_VELNED_ITOW = 0     # GPS time of week (ms)
OFFSET_VELNED_VELN = 4     # North velocity component (cm/s)
OFFSET_VELNED_VELE = 8     # East velocity component (cm/s)
OFFSET_VELNED_VELD = 12    # Down velocity component (cm/s)
OFFSET_VELNED_SPEED = 16   # Speed (3-D) (cm/s)
OFFSET_VELNED_GSPEED = 20  # Ground Speed (2-D) (cm/s)
OFFSET_VELNED_HEADING = 24 # Heading of motion 2-D (deg * 1e-5)
OFFSET_VELNED_SACC = 28    # Speed accuracy estimate (cm/s)
OFFSET_VELNED_CACC = 32    # Course/Heading accuracy estimate (deg * 1e-5)

# CFG-PRT Offsets
OFFSET_PRT_PORTID = 0      # Port Identifier Number
OFFSET_PRT_RESERVED1 = 1   # Reserved
OFFSET_PRT_TXREADY = 2     # TX Ready PIN Configuration
OFFSET_PRT_MODE = 4        # UART Mode Flags
OFFSET_PRT_BAUDRATE = 8    # Baudrate (bits/s)
OFFSET_PRT_INPROTO = 12    # Input Protocol Mask
OFFSET_PRT_OUTPROTO = 14   # Output Protocol Mask
OFFSET_PRT_FLAGS = 16      # Flags bit mask
OFFSET_PRT_RESERVED2 = 18  # Reserved

# CFG-MSG Offsets
OFFSET_MSG_CLASS = 0       # Message Class
OFFSET_MSG_ID = 1         # Message Identifier
OFFSET_MSG_RATE = 2       # Send rate on current port

# CFG-NAV5 Offsets
OFFSET_NAV5_MASK = 0       # Parameters Bitmask
OFFSET_NAV5_DYNMODEL = 2   # Dynamic Platform Model
OFFSET_NAV5_FIXMODE = 3    # Position Fixing Mode
OFFSET_NAV5_FIXALT = 4     # Fixed Altitude (m) MSL
OFFSET_NAV5_FIXALTVAR = 8  # Fixed Altitude Variance (m^2)
OFFSET_NAV5_MINELEV = 12   # Minimum Elevation for GNSS (deg)
OFFSET_NAV5_DRLIMIT = 13   # Maximum time to perform dead reckoning (s)
OFFSET_NAV5_PDOP = 14      # Position DOP Mask
OFFSET_NAV5_TDOP = 16      # Time DOP Mask
OFFSET_NAV5_PACC = 18      # Position Accuracy Mask (m)
OFFSET_NAV5_TACC = 20      # Time Accuracy Mask (m)
OFFSET_NAV5_STATICHOLD = 22 # Static Hold Threshold (cm/s)
OFFSET_NAV5_DGPSTO = 23    # DGPS timeout (s)

# CFG-RATE Offsets
OFFSET_RATE_MEASRATE = 0   # Measurement Rate (ms)
OFFSET_RATE_NAVRATE = 2    # Navigation Rate (cycles)
OFFSET_RATE_TIMEREF = 4    # Time Reference

# CFG-GNSS Offsets
OFFSET_GNSS_VERSION = 0    # Message Version
OFFSET_GNSS_NUMTRKCHHW = 1 # Number of tracking channels hardware
OFFSET_GNSS_NUMTRCHUSE = 2 # Number of tracking channels to use
OFFSET_GNSS_NUMCONFIG = 3  # Number of configurations to follow

# MON-VER String Offsets and Sizes
OFFSET_VER_SW = 0          # Software version string
OFFSET_VER_HW = 30         # Hardware version string
OFFSET_VER_EXT = 40        # Extension string start
SIZE_VER_STRING = 30       # Size of each version string

# MON-HW Offsets
OFFSET_HW_PINSEL = 0       # Mask of Pins Set as Peripheral/PIO
OFFSET_HW_PINBANK = 4      # Mask of Pins Set as Bank A/B
OFFSET_HW_PINDIR = 8       # Mask of Pins Set as Input/Output
OFFSET_HW_PINVAL = 12      # Mask of Pins Value Low/High
OFFSET_HW_NOISE = 16       # Noise Level
OFFSET_HW_AGCCOUNT = 18    # AGC Monitor (counts SIGHI xor SIGLO, range 0 to 8191)
OFFSET_HW_ANTSTAT = 20     # Antenna Status
OFFSET_HW_ANTPWR = 21      # Antenna Power Status
OFFSET_HW_RTCSTAT = 22     # RTC Status
OFFSET_HW_RESERVED1 = 23   # Reserved
OFFSET_HW_USEDMASK = 24    # Mask of Pins that are Used by the Virtual Pin Manager
OFFSET_HW_VP = 28          # Array of Pin Mappings for each of the 17 Physical Pins
OFFSET_HW_JAMIND = 45      # CW Jamming Indicator, scaled (0 = no CW jamming, 255 = strong CW jamming)
OFFSET_HW_RESERVED2 = 46   # Reserved
OFFSET_HW_PINIRQ = 48      # Mask of Pins Value using the PIO Irq
OFFSET_HW_PULLH = 52       # Mask of Pins Value using the PIO Pull High Resistor
OFFSET_HW_PULLL = 56       # Mask of Pins Value using the PIO Pull Low Resistor

# MON-HW Antenna Status Values
ANT_INIT = 0              # Antenna init
ANT_DONTKNOW = 1         # Antenna status unknown
ANT_OK = 2               # Antenna is OK
ANT_SHORT = 3            # Antenna short
ANT_OPEN = 4             # Antenna open

# MON-HW Antenna Power Status Values
ANT_OFF = 0              # Antenna power is off
ANT_ON = 1              # Antenna power is on
ANT_PWR_SHORT = 2       # Antenna power short circuit

# MON-IO Offsets
OFFSET_IO_RXBYTES = 0      # Number of bytes ever received
OFFSET_IO_TXBYTES = 4      # Number of bytes ever sent
OFFSET_IO_PARITYERRS = 8   # Number of parity errors
OFFSET_IO_FRAMINGERRS = 10 # Number of framing errors
OFFSET_IO_OVERRUNERRS = 12 # Number of overrun errors
OFFSET_IO_BREAKCOND = 14   # Number of break conditions
OFFSET_IO_RXBUSY = 16      # Receiver busy counts
OFFSET_IO_TXBUSY = 18      # Transmitter busy counts

# MON-MSGPP Offsets
OFFSET_MSGPP_MSG1 = 0      # Message parse and process counts for port 1
OFFSET_MSGPP_MSG2 = 16     # Message parse and process counts for port 2
OFFSET_MSGPP_MSG3 = 32     # Message parse and process counts for port 3
OFFSET_MSGPP_MSG4 = 48     # Message parse and process counts for port 4
OFFSET_MSGPP_MSG5 = 64     # Message parse and process counts for port 5
OFFSET_MSGPP_MSG6 = 80     # Message parse and process counts for port 6
OFFSET_MSGPP_SKIPPED = 96  # Number of skipped bytes

# MON-RXBUF Offsets
OFFSET_RXBUF_PENDING = 0   # Number of bytes pending in receiver buffer for each target
OFFSET_RXBUF_USAGE = 12    # Maximum usage receiver buffer for each target
OFFSET_RXBUF_PEAKUSAGE = 24 # Maximum usage receiver buffer for each target

# MON-TXBUF Offsets
OFFSET_TXBUF_PENDING = 0   # Number of bytes pending in transmitter buffer for each target
OFFSET_TXBUF_USAGE = 12    # Maximum usage transmitter buffer for each target
OFFSET_TXBUF_PEAKUSAGE = 24 # Maximum usage transmitter buffer for each target
OFFSET_TXBUF_TPENDING = 26 # Number of pending bytes total for all ports
OFFSET_TXBUF_TUSAGE = 24   # Buffer usage total for all ports

# MON-HW2 Offsets
OFFSET_HW2_OFSI = 0        # Imbalance of I-part of complex signal
OFFSET_HW2_MAGNI = 1       # Magnitude of I-part of complex signal
OFFSET_HW2_OFSQ = 2        # Imbalance of Q-part of complex signal
OFFSET_HW2_MAGNQ = 3       # Magnitude of Q-part of complex signal
OFFSET_HW2_CFGSRC = 4      # Configuration Source
OFFSET_HW2_RESERVED1 = 5   # Reserved 1
OFFSET_HW2_POSTSTATUS = 24 # POST Status
OFFSET_HW2_RESERVED2 = 25  # Reserved 2

# TIM-TP Offsets
OFFSET_TP_TOWMS = 0        # Time Pulse Time of Week (ms)
OFFSET_TP_TOWSUB = 4       # Submillisecond Part of ToW (ms * 2^32)
OFFSET_TP_QERR = 8         # Quantization Error (ps)
OFFSET_TP_WEEK = 12        # Week Number
OFFSET_TP_FLAGS = 14       # Flags
OFFSET_TP_REFINFO = 15     # Time Reference Information

# TIM-SVIN Offsets
OFFSET_SVIN_DUR = 0        # Survey-in duration (s)
OFFSET_SVIN_MEANX = 4      # Mean ECEF X position (cm)
OFFSET_SVIN_MEANY = 8      # Mean ECEF Y position (cm)
OFFSET_SVIN_MEANZ = 12     # Mean ECEF Z position (cm)
OFFSET_SVIN_MEANV = 16     # Mean position variance (mm^2)
OFFSET_SVIN_OBS = 20       # Number of position observations
OFFSET_SVIN_VALID = 24     # Survey-in position valid flag
OFFSET_SVIN_ACTIVE = 25    # Survey-in in progress flag

# LOG-INFO Offsets
OFFSET_INFO_VERSION = 0     # Message Version
OFFSET_INFO_RESERVED1 = 1   # Reserved
OFFSET_INFO_CAPACITY = 2    # Filestore Capacity (bytes)
OFFSET_INFO_MAXSIZE = 10    # Maximum Size of Log (bytes)
OFFSET_INFO_CURSIZE = 14    # Current Size of Log (bytes)
OFFSET_INFO_ENTRIES = 18    # Number of Entries in Log
OFFSET_INFO_OLDESTYR = 22   # Oldest Entry (year)
OFFSET_INFO_OLDESTMON = 24  # Oldest Entry (month)
OFFSET_INFO_OLDESTDAY = 25  # Oldest Entry (day)
OFFSET_INFO_OLDESTHR = 26   # Oldest Entry (hour)
OFFSET_INFO_OLDESTMIN = 27  # Oldest Entry (minute)
OFFSET_INFO_OLDESTSEC = 28  # Oldest Entry (second)
OFFSET_INFO_NEWESTYR = 34   # Newest Entry (year)
OFFSET_INFO_NEWESTMON = 36  # Newest Entry (month)
OFFSET_INFO_NEWESTDAY = 37  # Newest Entry (day)
OFFSET_INFO_NEWESTHR = 38   # Newest Entry (hour)
OFFSET_INFO_NEWESTMIN = 39  # Newest Entry (minute)
OFFSET_INFO_NEWESTSEC = 40  # Newest Entry (second)

# LOG-CREATE Offsets
OFFSET_CREATE_VERSION = 0   # Message Version
OFFSET_CREATE_LOGCFG = 1    # Config Flags
OFFSET_CREATE_RESERVED1 = 2 # Reserved
OFFSET_CREATE_LOGSIZE = 3   # Size of Log (bytes)
OFFSET_CREATE_USERTYPE = 4  # User Defined Type

# LOG-RETRIEVE Offsets
OFFSET_RETRIEVE_START = 0   # Index of first entry to retrieve
OFFSET_RETRIEVE_COUNT = 4   # Number of entries to retrieve
OFFSET_RETRIEVE_VERSION = 8 # Message Version

# Bitfield Masks
MASK_FIXTYPE = 0x0F        # Navigation Fix Type mask
MASK_FLAGS = 0x01          # Flags mask for various messages
MASK_DGPS = 0x02          # DGPS Input Used mask
MASK_WKN_VALID = 0x04     # Week Number Valid mask
MASK_TOW_VALID = 0x08     # Time of Week Valid mask
MASK_UTC_VALID = 0x10     # UTC Time Valid mask
MASK_DATE_VALID = 0x20    # Date Valid mask
MASK_TIME_VALID = 0x40    # Time of Day Valid mask

# Port Types
PORT_DDC = 0              # DDC (I2C compatible)
PORT_UART1 = 1           # UART 1
PORT_UART2 = 2           # UART 2
PORT_USB = 3             # USB
PORT_SPI = 4             # SPI

# Dynamic Platform Models
DYN_MODEL_PORTABLE = 0    # Portable
DYN_MODEL_STATIONARY = 2  # Stationary
DYN_MODEL_PEDESTRIAN = 3  # Pedestrian
DYN_MODEL_AUTOMOTIVE = 4  # Automotive
DYN_MODEL_SEA = 5        # Sea
DYN_MODEL_AIR1 = 6       # Airborne with <1g Acceleration
DYN_MODEL_AIR2 = 7       # Airborne with <2g Acceleration
DYN_MODEL_AIR4 = 8       # Airborne with <4g Acceleration
DYN_MODEL_WRIST = 9      # Wrist Worn Watch

# NAV-CLOCK Offsets
OFFSET_CLOCK_ITOW = 0    # GPS time of week (ms)
OFFSET_CLOCK_BIAS = 4    # Clock bias (ns)
OFFSET_CLOCK_DRIFT = 8   # Clock drift (ns/s)
OFFSET_CLOCK_TACC = 12   # Time accuracy estimate (ns)
OFFSET_CLOCK_FACC = 16   # Frequency accuracy estimate (ps/s)

# NAV-TIMEGPS Offsets
OFFSET_TIMEGPS_ITOW = 0    # GPS time of week (ms)
OFFSET_TIMEGPS_FTOW = 4    # Fractional part of iTOW (ns)
OFFSET_TIMEGPS_WEEK = 8    # GPS week number
OFFSET_TIMEGPS_LEAPS = 10  # GPS leap seconds (s)
OFFSET_TIMEGPS_VALID = 11  # Validity flags
OFFSET_TIMEGPS_TACC = 12   # Time accuracy estimate (ns)

# NAV-TIMEUTC Offsets
OFFSET_TIMEUTC_ITOW = 0    # GPS time of week (ms)
OFFSET_TIMEUTC_TACC = 4    # Time accuracy estimate (ns)
OFFSET_TIMEUTC_NANO = 8    # Fraction of second (-1e9..1e9)
OFFSET_TIMEUTC_YEAR = 12   # Year (1999..2099)
OFFSET_TIMEUTC_MONTH = 14  # Month (1..12)
OFFSET_TIMEUTC_DAY = 15    # Day of month (1..31)
OFFSET_TIMEUTC_HOUR = 16   # Hour of day (0..23)
OFFSET_TIMEUTC_MIN = 17    # Minute of hour (0..59)
OFFSET_TIMEUTC_SEC = 18    # Seconds of minute (0..60)
OFFSET_TIMEUTC_VALID = 19  # Validity flags

# NAV-ODO Offsets
OFFSET_ODO_VERSION = 0     # Message version
OFFSET_ODO_RESERVED1 = 1   # Reserved bytes
OFFSET_ODO_ITOW = 4       # GPS time of week (ms)
OFFSET_ODO_DISTANCE = 8    # Ground distance since last reset (m)
OFFSET_ODO_TOTAL = 12      # Total cumulative ground distance (m)
OFFSET_ODO_DISTANCESTD = 16 # Ground distance accuracy (1-sigma) (m)

# NAV-AOPSTATUS Offsets
OFFSET_AOP_ITOW = 0        # GPS time of week (ms)
OFFSET_AOP_CONFIG = 4      # AssistNow Autonomous configuration
OFFSET_AOP_STATUS = 5      # AssistNow Autonomous subsystem status
OFFSET_AOP_RESERVED1 = 6   # Reserved bytes
OFFSET_AOP_RESERVED2 = 7   # Reserved bytes
OFFSET_AOP_AVAIL = 8       # AssistNow Autonomous data availability 

# CFG-ANT Offsets
OFFSET_ANT_FLAGS = 0       # Antenna Flag Mask
OFFSET_ANT_PINS = 2        # Antenna Pin Configuration

# CFG-PM Offsets
OFFSET_PM_VERSION = 0      # Message Version
OFFSET_PM_RESERVED1 = 1    # Reserved
OFFSET_PM_RESERVED2 = 2    # Reserved
OFFSET_PM_RESERVED3 = 3    # Reserved
OFFSET_PM_FLAGS = 4        # Power Management Flags
OFFSET_PM_UPDATEPERIOD = 8 # Position update period (ms)
OFFSET_PM_SEARCHPERIOD = 10 # Acquisition retry period (ms)
OFFSET_PM_GRIDOFFSET = 12  # Grid offset relative to update period
OFFSET_PM_ONTIME = 14      # Time to stay in Tracking state (s)
OFFSET_PM_MINACQTIME = 16  # Minimum time to stay in Acquisition state (s)

# CFG-RINV Offsets
OFFSET_RINV_FLAGS = 0      # Remote Inventory Flags
OFFSET_RINV_DATA = 1       # Data (variable length)

# CFG-ITFM Offsets
OFFSET_ITFM_CONFIG = 0     # Interference Monitor Configuration
OFFSET_ITFM_CONFIG2 = 4    # Extra Settings for Interference Monitor

# CFG-LOGFILTER Offsets
OFFSET_LOGFILTER_VERSION = 0    # Message Version
OFFSET_LOGFILTER_FLAGS = 4      # Flags
OFFSET_LOGFILTER_MININTERVAL = 6 # Minimum time interval between log points
OFFSET_LOGFILTER_TIMETHRESH = 8  # Time threshold
OFFSET_LOGFILTER_SPEEDTHRESH = 10 # Speed threshold

# CFG-TMODE Offsets
OFFSET_TMODE_TIMEMODE = 0  # Time Mode
OFFSET_TMODE_RESERVED1 = 1 # Reserved
OFFSET_TMODE_FLAGS = 2     # Mode Flags
OFFSET_TMODE_ECEFX = 4     # ECEF X coordinate
OFFSET_TMODE_ECEFY = 8     # ECEF Y coordinate
OFFSET_TMODE_ECEFZ = 12    # ECEF Z coordinate

# CFG-SBAS Offsets
OFFSET_SBAS_MODE = 0       # SBAS Mode
OFFSET_SBAS_USAGE = 1      # SBAS Usage
OFFSET_SBAS_MAXSBAS = 2    # Maximum Number of SBAS channels
OFFSET_SBAS_SCANMODE2 = 3  # Continuation of scanmode bitmask
OFFSET_SBAS_SCANMODE1 = 4  # Which SBAS PRNs to search for

# CFG-USB Offsets
OFFSET_USB_VENDORID = 0    # Vendor ID
OFFSET_USB_PRODUCTID = 2   # Product ID
OFFSET_USB_RESERVED1 = 4   # Reserved
OFFSET_USB_RESERVED2 = 6   # Reserved
OFFSET_USB_POWERCONSUMP = 8 # Power Consumption
OFFSET_USB_FLAGS = 10      # USB Flags
OFFSET_USB_VENDORSTR = 12  # Vendor String (32 chars)
OFFSET_USB_PRODUCTSTR = 44 # Product String (32 chars)
OFFSET_USB_SERIALSTR = 76  # Serial Number String (32 chars)

# SBAS Usage Flags
SBAS_USAGE_RANGE = 0x01    # Use SBAS for ranging
SBAS_USAGE_DIFF = 0x02     # Use SBAS for differential corrections
SBAS_USAGE_INTEGRITY = 0x04 # Use SBAS for integrity information

# SBAS Mode Flags
SBAS_MODE_ENABLED = 0x01   # SBAS Enabled
SBAS_MODE_TEST = 0x02      # SBAS Test Mode

# TIM-TOS Offsets
OFFSET_TOS_VERSION = 0     # Message version (0x00 for this version)
OFFSET_TOS_GNSSID = 1     # GNSS ID
OFFSET_TOS_RESERVED1 = 2  # Reserved
OFFSET_TOS_FLAGS = 3      # Flags
OFFSET_TOS_YEAR = 4       # Year (1-65635) or zero for no time
OFFSET_TOS_MONTH = 6      # Month (1-12)
OFFSET_TOS_DAY = 7        # Day (1-31)
OFFSET_TOS_HOUR = 8       # Hour (0-23)
OFFSET_TOS_MINUTE = 9     # Minute (0-59)
OFFSET_TOS_SECOND = 10    # Second (0-60)
OFFSET_TOS_RESERVED2 = 11 # Reserved
OFFSET_TOS_SUBINT = 12    # Sub-second interval
OFFSET_TOS_INTLEN = 16    # Integration length
OFFSET_TOS_RESERVED3 = 20 # Reserved
OFFSET_TOS_INTSTAT = 24   # Integration status
OFFSET_TOS_RESERVED4 = 25 # Reserved
OFFSET_TOS_SLOPE = 28     # Slope of observation
OFFSET_TOS_RESERVED5 = 32 # Reserved
OFFSET_TOS_HPM = 36       # High-precision multiplier
OFFSET_TOS_RESERVED6 = 40 # Reserved

# TIM-SMEAS Offsets
OFFSET_SMEAS_VERSION = 0  # Message version (0x00 for this version)
OFFSET_SMEAS_RESERVED1 = 1 # Reserved
OFFSET_SMEAS_RESERVED2 = 2 # Reserved
OFFSET_SMEAS_FLAGS = 3    # Flags
OFFSET_SMEAS_PERIOD = 4   # Nominal period
OFFSET_SMEAS_INTOSC = 8   # Internal oscillator frequency
OFFSET_SMEAS_EXTOSC = 10  # External oscillator frequency

# NAV-SAT Additional Offsets
OFFSET_SAT_GNSSID = 0     # GNSS identifier
OFFSET_SAT_SVID = 1       # Satellite identifier
OFFSET_SAT_CNO = 2        # Carrier to noise ratio (dBHz)
OFFSET_SAT_ELEV = 3       # Elevation (deg)
OFFSET_SAT_AZIM = 4       # Azimuth (deg)
OFFSET_SAT_PRRES = 6      # Pseudo range residual (m)
OFFSET_SAT_FLAGS = 8      # Flags

# NAV-SAT Flag Bits
SAT_FLAGS_QUALITY_MASK = 0x07     # Signal quality indicator mask
SAT_FLAGS_SV_USED = 0x08          # Signal used in navigation
SAT_FLAGS_HEALTH_MASK = 0x30      # Health flag
SAT_FLAGS_DIFFCORR = 0x40         # Differential correction available
SAT_FLAGS_SMOOTHED = 0x80         # Carrier smoothed pseudorange used
SAT_FLAGS_ORBITSOURCE_MASK = 0x700 # Orbit source
SAT_FLAGS_EPHAVAIL = 0x800        # Ephemeris available
SAT_FLAGS_ALMAVAIL = 0x1000       # Almanac available
SAT_FLAGS_ANOAVAIL = 0x2000       # AssistNow Offline data available
SAT_FLAGS_AOPAVAIL = 0x4000       # AssistNow Autonomous data available

# RXM-RAW Offsets
OFFSET_RAW_RCVTOW = 0    # Measurement time of week
OFFSET_RAW_WEEK = 8      # GPS week number
OFFSET_RAW_NUMSV = 10    # Number of satellites
OFFSET_RAW_RESERVED1 = 11 # Reserved

# RXM-RAWX Offsets
OFFSET_RAWX_RCVTOW = 0   # Receiver time of week
OFFSET_RAWX_WEEK = 8     # GPS week number
OFFSET_RAWX_LEAPS = 10   # GPS leap seconds
OFFSET_RAWX_NUMSV = 11   # Number of satellites following
OFFSET_RAWX_RECSTAT = 12 # Receiver tracking status
OFFSET_RAWX_VERSION = 13 # Message version
OFFSET_RAWX_RESERVED1 = 14 # Reserved

# RXM-SFRBX Offsets
OFFSET_SFRBX_GNSSID = 0  # GNSS identifier
OFFSET_SFRBX_SVID = 1    # Satellite identifier
OFFSET_SFRBX_RESERVED1 = 2 # Reserved
OFFSET_SFRBX_FREQID = 3  # Only used for GLONASS
OFFSET_SFRBX_NUMWORDS = 4 # Number of data words
OFFSET_SFRBX_RESERVED2 = 5 # Reserved
OFFSET_SFRBX_VERSION = 6 # Message version
OFFSET_SFRBX_RESERVED3 = 7 # Reserved
