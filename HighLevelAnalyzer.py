from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import struct
from ubx_constants import *

# UBX Protocol States
class State:
    SYNC_CHAR1 = 0  # Looking for SYNC1 (0xB5)
    SYNC_CHAR2 = 1  # Looking for SYNC2 (0x62)
    CLASS = 2       # Message class
    ID = 3         # Message ID
    LENGTH_LSB = 4  # Length lower byte
    LENGTH_MSB = 5  # Length upper byte
    PAYLOAD = 6     # Payload bytes
    CK_A = 7       # Checksum byte A
    CK_B = 8       # Checksum byte B

class Hla(HighLevelAnalyzer):
    result_types = {
        'ubx_frame': {
            'format': 'UBX: {{data.description}}',
            'columns': [
                ('Class', 'class_name'),
                ('ID', 'msg_id'),
                ('Length', 'length'),
                ('Details', 'details')
            ]
        },
        'ubx_error': {
            'format': 'UBX Error: {{data.error}}'
        }
    }

    def __init__(self):
        self.reset_state()
        
    def reset_state(self):
        """Reset all state variables"""
        self.state = State.SYNC_CHAR1
        self.msg_class = 0
        self.msg_id = 0
        self.length = 0
        self.payload = []
        self.ck_a = 0
        self.ck_b = 0
        self.calc_ck_a = 0
        self.calc_ck_b = 0
        self.frame_start_time = None
        
    def parse_nav_pvt(self, payload):
        """Parse NAV-PVT message payload"""
        if len(payload) < 92:
            return "Incomplete NAV-PVT message"
            
        # Extract key fields using list indices
        iTOW = payload[OFFSET_PVT_ITOW] | (payload[OFFSET_PVT_ITOW + 1] << 8) | \
               (payload[OFFSET_PVT_ITOW + 2] << 16) | (payload[OFFSET_PVT_ITOW + 3] << 24)
        year = payload[OFFSET_PVT_YEAR] | (payload[OFFSET_PVT_YEAR + 1] << 8)
        month = payload[OFFSET_PVT_MONTH]
        day = payload[OFFSET_PVT_DAY]
        hour = payload[OFFSET_PVT_HOUR]
        min = payload[OFFSET_PVT_MIN]
        sec = payload[OFFSET_PVT_SEC]
        valid = payload[OFFSET_PVT_VALID]
        fixType = payload[OFFSET_PVT_FIX]
        flags = payload[OFFSET_PVT_FLAGS]
        numSV = payload[OFFSET_PVT_NUMSV]
        lon = payload[OFFSET_PVT_LON] | (payload[OFFSET_PVT_LON + 1] << 8) | \
              (payload[OFFSET_PVT_LON + 2] << 16) | (payload[OFFSET_PVT_LON + 3] << 24)
        lat = payload[OFFSET_PVT_LAT] | (payload[OFFSET_PVT_LAT + 1] << 8) | \
              (payload[OFFSET_PVT_LAT + 2] << 16) | (payload[OFFSET_PVT_LAT + 3] << 24)
        height = payload[OFFSET_PVT_HEIGHT] | (payload[OFFSET_PVT_HEIGHT + 1] << 8) | \
                 (payload[OFFSET_PVT_HEIGHT + 2] << 16) | (payload[OFFSET_PVT_HEIGHT + 3] << 24)
        hMSL = payload[OFFSET_PVT_HMSL] | (payload[OFFSET_PVT_HMSL + 1] << 8) | \
               (payload[OFFSET_PVT_HMSL + 2] << 16) | (payload[OFFSET_PVT_HMSL + 3] << 24)
        
        # Convert lat/lon to degrees
        lat_deg = lat * 1e-7
        lon_deg = lon * 1e-7
        
        # Determine fix type string
        fix_types = {
            FIX_NONE: "No Fix",
            FIX_DEAD_RECKONING: "Dead Reckoning",
            FIX_2D: "2D Fix",
            FIX_3D: "3D Fix",
            FIX_GPS_DEAD_RECKONING: "GNSS + Dead Reckoning",
            FIX_TIME_ONLY: "Time only"
        }
        fix_str = fix_types.get(fixType, f"Unknown ({fixType})")
        
        # Format time
        time_str = f"{year}-{month:02d}-{day:02d} {hour:02d}:{min:02d}:{sec:02d}"
        
        return (f"Time: {time_str}, Fix: {fix_str}, Sats: {numSV}, "
                f"Pos: {lat_deg:.6f}°, {lon_deg:.6f}°, Alt: {hMSL/1000:.1f}m")

    def parse_nav_status(self, payload):
        """Parse NAV-STATUS message payload"""
        if len(payload) < 16:
            return "Incomplete NAV-STATUS message"
            
        iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
        gpsFix = payload[4]
        flags = payload[5]
        fixStat = payload[6]
        flags2 = payload[7]
        
        fix_types = {
            0x00: "No Fix",
            0x01: "Dead Reckoning",
            0x02: "2D Fix",
            0x03: "3D Fix",
            0x04: "GPS + DR",
            0x05: "Time Only"
        }
        
        fix_str = fix_types.get(gpsFix, f"Unknown ({gpsFix})")
        return f"Fix: {fix_str}, Flags: 0x{flags:02X}"

    def parse_cfg_msg(self, payload):
        """Parse CFG message payload"""
        if len(payload) == 0:
            msg_names = {
                0x00: "PRT",
                0x01: "MSG",
                0x08: "RATE",
                0x13: "ANT",
                0x16: "SBAS",
                0x1D: "TMODE",
                0x24: "NAV5",
                0x32: "PM",
                0x34: "RINV",
                0x39: "ITFM",
                0x3E: "GNSS",
                0x47: "LOGFILTER",
                0x86: "USB"
            }
            msg_name = msg_names.get(self.msg_id, f"0x{self.msg_id:02X}")
            return f"Poll CFG-{msg_name} configuration"
            
        if self.msg_id == 0x00:  # CFG-PRT
            if len(payload) >= 20:
                portID = payload[OFFSET_PRT_PORTID]
                txReady = payload[OFFSET_PRT_TXREADY] | (payload[OFFSET_PRT_TXREADY + 1] << 8)
                mode = payload[OFFSET_PRT_MODE] | (payload[OFFSET_PRT_MODE + 1] << 8) | \
                       (payload[OFFSET_PRT_MODE + 2] << 16) | (payload[OFFSET_PRT_MODE + 3] << 24)
                baudRate = payload[OFFSET_PRT_BAUDRATE] | (payload[OFFSET_PRT_BAUDRATE + 1] << 8) | \
                          (payload[OFFSET_PRT_BAUDRATE + 2] << 16) | (payload[OFFSET_PRT_BAUDRATE + 3] << 24)
                inProtoMask = payload[OFFSET_PRT_INPROTO] | (payload[OFFSET_PRT_INPROTO + 1] << 8)
                outProtoMask = payload[OFFSET_PRT_OUTPROTO] | (payload[OFFSET_PRT_OUTPROTO + 1] << 8)
                flags = payload[OFFSET_PRT_FLAGS] | (payload[OFFSET_PRT_FLAGS + 1] << 8)
                
                port_types = {
                    PORT_DDC: "DDC",
                    PORT_UART1: "UART1",
                    PORT_UART2: "UART2",
                    PORT_USB: "USB",
                    PORT_SPI: "SPI"
                }
                port_name = port_types.get(portID, f"Port{portID}")
                return f"PRT: {port_name} Baud={baudRate} In=0x{inProtoMask:04X} Out=0x{outProtoMask:04X}"
                
        elif self.msg_id == 0x01:  # CFG-MSG
            if len(payload) == 3:
                msg_class = payload[OFFSET_MSG_CLASS]
                msg_id = payload[OFFSET_MSG_ID]
                rate = payload[OFFSET_MSG_RATE]
                
                class_descriptions = {
                    CLASS_NAV: "NAV",
                    CLASS_RXM: "RXM",
                    CLASS_INF: "INF",
                    CLASS_ACK: "ACK",
                    CLASS_CFG: "CFG",
                    CLASS_UPD: "UPD",
                    CLASS_MON: "MON",
                    CLASS_TIM: "TIM",
                    CLASS_MGA: "MGA",
                    CLASS_LOG: "LOG",
                    CLASS_SEC: "SEC",
                    CLASS_HNR: "HNR"
                }
                msg_class_name = class_descriptions.get(msg_class, f"Unknown(0x{msg_class:02X})")
                return f"Configure {msg_class_name}-0x{msg_id:02X} rate: {rate}Hz"
                
        elif self.msg_id == 0x24:  # CFG-NAV5
            if len(payload) >= 36:
                mask = payload[OFFSET_NAV5_MASK] | (payload[OFFSET_NAV5_MASK + 1] << 8)
                dyn_model = payload[OFFSET_NAV5_DYNMODEL]
                fix_mode = payload[OFFSET_NAV5_FIXMODE]
                fixed_alt = payload[OFFSET_NAV5_FIXALT] | (payload[OFFSET_NAV5_FIXALT + 1] << 8) | \
                           (payload[OFFSET_NAV5_FIXALT + 2] << 16) | (payload[OFFSET_NAV5_FIXALT + 3] << 24)
                fixed_alt_var = payload[OFFSET_NAV5_FIXALTVAR] | (payload[OFFSET_NAV5_FIXALTVAR + 1] << 8) | \
                               (payload[OFFSET_NAV5_FIXALTVAR + 2] << 16) | (payload[OFFSET_NAV5_FIXALTVAR + 3] << 24)
                min_elev = payload[OFFSET_NAV5_MINELEV]
                dr_limit = payload[OFFSET_NAV5_DRLIMIT]
                pdop = (payload[OFFSET_NAV5_PDOP] | (payload[OFFSET_NAV5_PDOP + 1] << 8)) * 0.1
                tdop = (payload[OFFSET_NAV5_TDOP] | (payload[OFFSET_NAV5_TDOP + 1] << 8)) * 0.1
                pacc = payload[OFFSET_NAV5_PACC] | (payload[OFFSET_NAV5_PACC + 1] << 8)
                tacc = payload[OFFSET_NAV5_TACC] | (payload[OFFSET_NAV5_TACC + 1] << 8)
                static_hold_thresh = payload[OFFSET_NAV5_STATICHOLD]
                dgps_timeout = payload[OFFSET_NAV5_DGPSTO]
                
                dyn_models = {
                    DYN_MODEL_PORTABLE: "Portable",
                    DYN_MODEL_STATIONARY: "Stationary",
                    DYN_MODEL_PEDESTRIAN: "Pedestrian",
                    DYN_MODEL_AUTOMOTIVE: "Automotive",
                    DYN_MODEL_SEA: "Sea",
                    DYN_MODEL_AIR1: "Airborne <1g",
                    DYN_MODEL_AIR2: "Airborne <2g",
                    DYN_MODEL_AIR4: "Airborne <4g",
                    DYN_MODEL_WRIST: "Wrist Worn"
                }
                
                fix_modes = {
                    1: "2D only",
                    2: "3D only",
                    3: "Auto 2D/3D"
                }
                
                model = dyn_models.get(dyn_model, f"Unknown ({dyn_model})")
                mode = fix_modes.get(fix_mode, f"Unknown ({fix_mode})")
                
                return (f"Model:{model} Mode:{mode} MinElev:{min_elev}° "
                       f"PDOP:{pdop:.1f} TDOP:{tdop:.1f}")
                
        elif self.msg_id == 0x08:  # CFG-RATE
            if len(payload) >= 6:
                meas_rate = payload[OFFSET_RATE_MEASRATE] | (payload[OFFSET_RATE_MEASRATE + 1] << 8)
                nav_rate = payload[OFFSET_RATE_NAVRATE] | (payload[OFFSET_RATE_NAVRATE + 1] << 8)
                time_ref = payload[OFFSET_RATE_TIMEREF] | (payload[OFFSET_RATE_TIMEREF + 1] << 8)
                
                time_refs = {
                    TIME_REF_UTC: "UTC",
                    TIME_REF_GPS: "GPS",
                    TIME_REF_GLONASS: "GLONASS",
                    TIME_REF_BEIDOU: "BeiDou",
                    TIME_REF_GALILEO: "Galileo"
                }
                
                ref = time_refs.get(time_ref, f"Unknown ({time_ref})")
                return f"Measurement Rate: {meas_rate}ms, Navigation Rate: {nav_rate} cycles, Time Reference: {ref}"
                
        elif self.msg_id == 0x3E:  # CFG-GNSS
            if len(payload) >= 4:
                version = payload[OFFSET_GNSS_VERSION]
                numTrkChHw = payload[OFFSET_GNSS_NUMTRKCHHW]
                numTrkChUse = payload[OFFSET_GNSS_NUMTRCHUSE]
                numConfigBlocks = payload[OFFSET_GNSS_NUMCONFIG]
                
                configs = []
                offset = 4
                for i in range(numConfigBlocks):
                    if offset + 8 <= len(payload):
                        gnssId = payload[offset]
                        resTrkCh = payload[offset + 1]
                        maxTrkCh = payload[offset + 2]
                        flags = payload[offset + 4] | (payload[offset + 5] << 8) | \
                               (payload[offset + 6] << 16) | (payload[offset + 7] << 24)
                        
                        enabled = (flags & MASK_FLAGS) != 0
                        
                        gnss_types = {
                            GNSS_GPS: "GPS",
                            GNSS_SBAS: "SBAS",
                            GNSS_GALILEO: "Galileo",
                            GNSS_BEIDOU: "BeiDou",
                            GNSS_IMES: "IMES",
                            GNSS_QZSS: "QZSS",
                            GNSS_GLONASS: "GLONASS"
                        }
                        gnss_name = gnss_types.get(gnssId, f"GNSS{gnssId}")
                        
                        configs.append(f"{gnss_name}({'En' if enabled else 'Dis'},{maxTrkCh}ch)")
                        offset += 8
                
                return f"GNSS Config: {', '.join(configs)}"
        
        elif self.msg_id == 0x13:  # CFG-ANT
            if len(payload) >= 4:
                flags = payload[OFFSET_ANT_FLAGS] | (payload[OFFSET_ANT_FLAGS + 1] << 8)
                pins = payload[OFFSET_ANT_PINS] | (payload[OFFSET_ANT_PINS + 1] << 8)
                return f"ANT: Flags=0x{flags:04X} Pins=0x{pins:04X}"
                
        elif self.msg_id == 0x32:  # CFG-PM
            if len(payload) >= 24:
                version = payload[OFFSET_PM_VERSION]
                flags = payload[OFFSET_PM_FLAGS] | (payload[OFFSET_PM_FLAGS + 1] << 8) | \
                       (payload[OFFSET_PM_FLAGS + 2] << 16) | (payload[OFFSET_PM_FLAGS + 3] << 24)
                updatePeriod = payload[OFFSET_PM_UPDATEPERIOD] | (payload[OFFSET_PM_UPDATEPERIOD + 1] << 8)
                searchPeriod = payload[OFFSET_PM_SEARCHPERIOD] | (payload[OFFSET_PM_SEARCHPERIOD + 1] << 8)
                gridOffset = payload[OFFSET_PM_GRIDOFFSET] | (payload[OFFSET_PM_GRIDOFFSET + 1] << 8)
                onTime = payload[OFFSET_PM_ONTIME] | (payload[OFFSET_PM_ONTIME + 1] << 8)
                minAcqTime = payload[OFFSET_PM_MINACQTIME] | (payload[OFFSET_PM_MINACQTIME + 1] << 8)
                return f"PM: Update={updatePeriod}ms Search={searchPeriod}ms OnTime={onTime}s Flags=0x{flags:08X}"
                
        elif self.msg_id == 0x34:  # CFG-RINV
            if len(payload) >= 1:
                flags = payload[OFFSET_RINV_FLAGS]
                data = bytes(payload[OFFSET_RINV_DATA:]).decode('ascii').rstrip('\0') if len(payload) > 1 else ""
                return f"RINV: Flags=0x{flags:02X} Data='{data}'"
                
        elif self.msg_id == 0x39:  # CFG-ITFM
            if len(payload) >= 8:
                config = payload[OFFSET_ITFM_CONFIG] | (payload[OFFSET_ITFM_CONFIG + 1] << 8) | \
                        (payload[OFFSET_ITFM_CONFIG + 2] << 16) | (payload[OFFSET_ITFM_CONFIG + 3] << 24)
                config2 = payload[OFFSET_ITFM_CONFIG2] | (payload[OFFSET_ITFM_CONFIG2 + 1] << 8) | \
                         (payload[OFFSET_ITFM_CONFIG2 + 2] << 16) | (payload[OFFSET_ITFM_CONFIG2 + 3] << 24)
                return f"ITFM: Config=0x{config:08X} Config2=0x{config2:08X}"
                
        elif self.msg_id == 0x47:  # CFG-LOGFILTER
            if len(payload) >= 12:
                version = payload[OFFSET_LOGFILTER_VERSION]
                flags = payload[OFFSET_LOGFILTER_FLAGS] | (payload[OFFSET_LOGFILTER_FLAGS + 1] << 8)
                minInterval = payload[OFFSET_LOGFILTER_MININTERVAL] | (payload[OFFSET_LOGFILTER_MININTERVAL + 1] << 8)
                timeThreshold = payload[OFFSET_LOGFILTER_TIMETHRESH] | (payload[OFFSET_LOGFILTER_TIMETHRESH + 1] << 8)
                speedThreshold = payload[OFFSET_LOGFILTER_SPEEDTHRESH] | (payload[OFFSET_LOGFILTER_SPEEDTHRESH + 1] << 8)
                return f"LOGFILTER: MinInt={minInterval}s TimeThresh={timeThreshold}s SpeedThresh={speedThreshold}m/s"
                
        elif self.msg_id == 0x1D:  # CFG-TMODE
            if len(payload) >= 28:
                timeMode = payload[OFFSET_TMODE_TIMEMODE]
                flags = payload[OFFSET_TMODE_FLAGS] | (payload[OFFSET_TMODE_FLAGS + 1] << 8)
                ecefX = payload[OFFSET_TMODE_ECEFX] | (payload[OFFSET_TMODE_ECEFX + 1] << 8) | \
                        (payload[OFFSET_TMODE_ECEFX + 2] << 16) | (payload[OFFSET_TMODE_ECEFX + 3] << 24)
                ecefY = payload[OFFSET_TMODE_ECEFY] | (payload[OFFSET_TMODE_ECEFY + 1] << 8) | \
                        (payload[OFFSET_TMODE_ECEFY + 2] << 16) | (payload[OFFSET_TMODE_ECEFY + 3] << 24)
                ecefZ = payload[OFFSET_TMODE_ECEFZ] | (payload[OFFSET_TMODE_ECEFZ + 1] << 8) | \
                        (payload[OFFSET_TMODE_ECEFZ + 2] << 16) | (payload[OFFSET_TMODE_ECEFZ + 3] << 24)
                mode_str = "Disabled" if timeMode == 0 else "Survey In" if timeMode == 1 else "Fixed"
                return f"TMODE: Mode={mode_str} Pos=({ecefX},{ecefY},{ecefZ})"
                
        elif self.msg_id == 0x16:  # CFG-SBAS
            if len(payload) >= 8:
                mode = payload[OFFSET_SBAS_MODE]
                usage = payload[OFFSET_SBAS_USAGE]
                maxSBAS = payload[OFFSET_SBAS_MAXSBAS]
                scanmode2 = payload[OFFSET_SBAS_SCANMODE2]
                scanmode1 = payload[OFFSET_SBAS_SCANMODE1] | (payload[OFFSET_SBAS_SCANMODE1 + 1] << 8) | \
                           (payload[OFFSET_SBAS_SCANMODE1 + 2] << 16) | (payload[OFFSET_SBAS_SCANMODE1 + 3] << 24)
                
                enabled = (mode & SBAS_MODE_ENABLED) != 0
                test = (mode & SBAS_MODE_TEST) != 0
                
                use_bits = []
                if usage & SBAS_USAGE_RANGE: use_bits.append("Range")
                if usage & SBAS_USAGE_DIFF: use_bits.append("Diff")
                if usage & SBAS_USAGE_INTEGRITY: use_bits.append("Integrity")
                
                return f"SBAS: {'En' if enabled else 'Dis'} Test:{'Y' if test else 'N'} Max:{maxSBAS} Use:{'+'.join(use_bits) if use_bits else 'None'}"
                
        elif self.msg_id == 0x86:  # CFG-USB
            if len(payload) >= 108:
                vendorID = payload[OFFSET_USB_VENDORID] | (payload[OFFSET_USB_VENDORID + 1] << 8)
                productID = payload[OFFSET_USB_PRODUCTID] | (payload[OFFSET_USB_PRODUCTID + 1] << 8)
                powerConsumption = payload[OFFSET_USB_POWERCONSUMP] | (payload[OFFSET_USB_POWERCONSUMP + 1] << 8)
                flags = payload[OFFSET_USB_FLAGS] | (payload[OFFSET_USB_FLAGS + 1] << 8)
                
                # Check if this is a poll request (all zeros)
                if all(b == 0 for b in payload):
                    return "Poll USB configuration"
                
                # Get null-terminated strings
                try:
                    vendor_str = bytes(payload[OFFSET_USB_VENDORSTR:OFFSET_USB_PRODUCTSTR]).decode('ascii').rstrip('\0')
                    product_str = bytes(payload[OFFSET_USB_PRODUCTSTR:OFFSET_USB_SERIALSTR]).decode('ascii').rstrip('\0')
                    serial_str = bytes(payload[OFFSET_USB_SERIALSTR:OFFSET_USB_SERIALSTR+32]).decode('ascii').rstrip('\0')
                    
                    # Only include strings if they're not empty
                    strings = []
                    if vendor_str:
                        strings.append(f"Vendor:'{vendor_str}'")
                    if product_str:
                        strings.append(f"Product:'{product_str}'")
                    if serial_str:
                        strings.append(f"Serial:'{serial_str}'")
                    
                    result = f"USB: VID:0x{vendorID:04X} PID:0x{productID:04X} Power:{powerConsumption}mA Flags:0x{flags:04X}"
                    if strings:
                        result += f" {' '.join(strings)}"
                    return result
                except:
                    return f"USB: VID:0x{vendorID:04X} PID:0x{productID:04X} Power:{powerConsumption}mA Flags:0x{flags:04X}"
            else:
                return "Incomplete USB configuration"
        
        # For other CFG messages or unknown formats, show raw bytes
        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"Payload: {payload_hex}"

    def parse_ack_msg(self, payload):
        """Parse ACK/NACK message payload"""
        if len(payload) != 2:
            return "Invalid ACK message length"
            
        cls_id = payload[0]
        msg_id = payload[1]
        
        class_descriptions = {
            0x01: "NAV",
            0x02: "RXM",
            0x04: "INF",
            0x05: "ACK",
            0x06: "CFG",
            0x09: "UPD",
            0x0A: "MON",
            0x0D: "TIM",
            0x13: "MGA",
            0x21: "LOG",
            0x27: "SEC",
            0x28: "HNR",
        }
        
        msg_names = {
            (0x06, 0x01): "MSG",
            (0x06, 0x3E): "GNSS",
            (0x0A, 0x04): "VER",
            (0x06, 0x08): "RATE",
            (0x06, 0x06): "NAV5",
            (0x06, 0x17): "PM2",
            (0x06, 0x24): "NAV5"
        }
        
        ack_class = class_descriptions.get(cls_id, f"Unknown(0x{cls_id:02X})")
        msg_name = msg_names.get((cls_id, msg_id), f"0x{msg_id:02X}")
        
        return f"{'ACK' if self.msg_id == 0x01 else 'NACK'} {ack_class}-{msg_name}"

    def format_raw_bytes(self):
        """Format all message bytes for display"""
        bytes_list = [0xB5, 0x62, self.msg_class, self.msg_id, 
                     self.length & 0xFF, (self.length >> 8) & 0xFF]
        bytes_list.extend(self.payload)
        bytes_list.extend([self.ck_a, self.ck_b])
        
        return ' '.join([f'0x{b:02X}' for b in bytes_list])

    def parse_nav_msg(self, payload):
        """Parse NAV class messages"""
        if len(payload) == 0:
            return "Poll navigation data"

        if self.msg_id == NAV_SAT:  # NAV-SAT
            if len(payload) >= 8:
                iTOW = payload[OFFSET_PVT_ITOW] | (payload[OFFSET_PVT_ITOW + 1] << 8) | \
                       (payload[OFFSET_PVT_ITOW + 2] << 16) | (payload[OFFSET_PVT_ITOW + 3] << 24)
                version = payload[4]
                numSvs = payload[5]
                reserved = payload[6:8]

                sats = []
                offset = 8
                for i in range(numSvs):
                    if offset + 12 <= len(payload):
                        gnssId = payload[offset + OFFSET_SAT_GNSSID]
                        svId = payload[offset + OFFSET_SAT_SVID]
                        cno = payload[offset + OFFSET_SAT_CNO]
                        elev = payload[offset + OFFSET_SAT_ELEV]
                        azim = payload[offset + OFFSET_SAT_AZIM] | (payload[offset + OFFSET_SAT_AZIM + 1] << 8)
                        prRes = payload[offset + OFFSET_SAT_PRRES] | (payload[offset + OFFSET_SAT_PRRES + 1] << 8)
                        flags = payload[offset + OFFSET_SAT_FLAGS] | (payload[offset + OFFSET_SAT_FLAGS + 1] << 8) | \
                               (payload[offset + OFFSET_SAT_FLAGS + 2] << 16) | (payload[offset + OFFSET_SAT_FLAGS + 3] << 24)
                        
                        quality = (flags & SAT_FLAGS_QUALITY_MASK)
                        used = (flags & SAT_FLAGS_SV_USED) != 0
                        health = (flags & SAT_FLAGS_HEALTH_MASK) >> 4
                        diffCorr = (flags & SAT_FLAGS_DIFFCORR) != 0
                        smoothed = (flags & SAT_FLAGS_SMOOTHED) != 0
                        ephAvail = (flags & SAT_FLAGS_EPHAVAIL) != 0
                        almAvail = (flags & SAT_FLAGS_ALMAVAIL) != 0
                        anoAvail = (flags & SAT_FLAGS_ANOAVAIL) != 0
                        aopAvail = (flags & SAT_FLAGS_AOPAVAIL) != 0
                        
                        gnss_types = {
                            GNSS_GPS: "GPS",
                            GNSS_SBAS: "SBAS",
                            GNSS_GALILEO: "Galileo",
                            GNSS_BEIDOU: "BeiDou",
                            GNSS_IMES: "IMES",
                            GNSS_QZSS: "QZSS",
                            GNSS_GLONASS: "GLONASS"
                        }
                        gnss_name = gnss_types.get(gnssId, f"GNSS{gnssId}")
                        
                        sat_info = f"{gnss_name}-{svId}({cno}dB,{elev}°)"
                        if used:
                            sat_info += "*"  # Mark used satellites
                        if diffCorr:
                            sat_info += "+"  # Mark differential corrected satellites
                        sats.append(sat_info)
                        
                        offset += 12
                
                return f"Sats({numSvs}): {', '.join(sats)}"
        
        elif self.msg_id == NAV_PVT:  # NAV-PVT
            return self.parse_nav_pvt(payload)
        elif self.msg_id == NAV_STATUS:  # NAV-STATUS
            if len(payload) >= 16:
                iTOW = payload[OFFSET_STATUS_ITOW] | (payload[OFFSET_STATUS_ITOW + 1] << 8) | \
                       (payload[OFFSET_STATUS_ITOW + 2] << 16) | (payload[OFFSET_STATUS_ITOW + 3] << 24)
                gpsFix = payload[OFFSET_STATUS_GPSFIX]
                flags = payload[OFFSET_STATUS_FLAGS]
                fixStat = payload[OFFSET_STATUS_FIXSTAT]
                flags2 = payload[OFFSET_STATUS_FLAGS2]
                
                fix_types = {
                    FIX_NONE: "No Fix",
                    FIX_DEAD_RECKONING: "Dead Reckoning",
                    FIX_2D: "2D Fix",
                    FIX_3D: "3D Fix",
                    FIX_GPS_DEAD_RECKONING: "GPS + DR",
                    FIX_TIME_ONLY: "Time Only"
                }
                
                fix_str = fix_types.get(gpsFix, f"Unknown ({gpsFix})")
                return f"Fix: {fix_str}, Flags: 0x{flags:02X}"
        elif self.msg_id == NAV_POSECEF:  # NAV-POSECEF
            if len(payload) >= 20:
                iTOW = payload[OFFSET_POSECEF_ITOW] | (payload[OFFSET_POSECEF_ITOW + 1] << 8) | \
                       (payload[OFFSET_POSECEF_ITOW + 2] << 16) | (payload[OFFSET_POSECEF_ITOW + 3] << 24)
                ecefX = payload[OFFSET_POSECEF_ECEFX] | (payload[OFFSET_POSECEF_ECEFX + 1] << 8) | \
                        (payload[OFFSET_POSECEF_ECEFX + 2] << 16) | (payload[OFFSET_POSECEF_ECEFX + 3] << 24)
                ecefY = payload[OFFSET_POSECEF_ECEFY] | (payload[OFFSET_POSECEF_ECEFY + 1] << 8) | \
                        (payload[OFFSET_POSECEF_ECEFY + 2] << 16) | (payload[OFFSET_POSECEF_ECEFY + 3] << 24)
                ecefZ = payload[OFFSET_POSECEF_ECEFZ] | (payload[OFFSET_POSECEF_ECEFZ + 1] << 8) | \
                        (payload[OFFSET_POSECEF_ECEFZ + 2] << 16) | (payload[OFFSET_POSECEF_ECEFZ + 3] << 24)
                pAcc = payload[OFFSET_POSECEF_PACC] | (payload[OFFSET_POSECEF_PACC + 1] << 8) | \
                       (payload[OFFSET_POSECEF_PACC + 2] << 16) | (payload[OFFSET_POSECEF_PACC + 3] << 24)
                return f"ECEF: X={ecefX/100}m Y={ecefY/100}m Z={ecefZ/100}m (±{pAcc/100}m)"
        elif self.msg_id == NAV_POSLLH:  # NAV-POSLLH
            if len(payload) >= 28:
                iTOW = payload[OFFSET_POSLLH_ITOW] | (payload[OFFSET_POSLLH_ITOW + 1] << 8) | \
                       (payload[OFFSET_POSLLH_ITOW + 2] << 16) | (payload[OFFSET_POSLLH_ITOW + 3] << 24)
                lon = payload[OFFSET_POSLLH_LON] | (payload[OFFSET_POSLLH_LON + 1] << 8) | \
                      (payload[OFFSET_POSLLH_LON + 2] << 16) | (payload[OFFSET_POSLLH_LON + 3] << 24)
                lat = payload[OFFSET_POSLLH_LAT] | (payload[OFFSET_POSLLH_LAT + 1] << 8) | \
                      (payload[OFFSET_POSLLH_LAT + 2] << 16) | (payload[OFFSET_POSLLH_LAT + 3] << 24)
                height = payload[OFFSET_POSLLH_HEIGHT] | (payload[OFFSET_POSLLH_HEIGHT + 1] << 8) | \
                        (payload[OFFSET_POSLLH_HEIGHT + 2] << 16) | (payload[OFFSET_POSLLH_HEIGHT + 3] << 24)
                hMSL = payload[OFFSET_POSLLH_HMSL] | (payload[OFFSET_POSLLH_HMSL + 1] << 8) | \
                       (payload[OFFSET_POSLLH_HMSL + 2] << 16) | (payload[OFFSET_POSLLH_HMSL + 3] << 24)
                hAcc = payload[OFFSET_POSLLH_HACC] | (payload[OFFSET_POSLLH_HACC + 1] << 8) | \
                       (payload[OFFSET_POSLLH_HACC + 2] << 16) | (payload[OFFSET_POSLLH_HACC + 3] << 24)
                vAcc = payload[OFFSET_POSLLH_VACC] | (payload[OFFSET_POSLLH_VACC + 1] << 8) | \
                       (payload[OFFSET_POSLLH_VACC + 2] << 16) | (payload[OFFSET_POSLLH_VACC + 3] << 24)
                return f"Pos: {lat*1e-7}°, {lon*1e-7}°, Alt: {hMSL/1000}m (±H:{hAcc/1000}m V:{vAcc/1000}m)"
        elif self.msg_id == NAV_DOP:  # NAV-DOP
            if len(payload) >= 18:
                iTOW = payload[OFFSET_DOP_ITOW] | (payload[OFFSET_DOP_ITOW + 1] << 8) | \
                       (payload[OFFSET_DOP_ITOW + 2] << 16) | (payload[OFFSET_DOP_ITOW + 3] << 24)
                gDOP = (payload[OFFSET_DOP_GDOP] | (payload[OFFSET_DOP_GDOP + 1] << 8)) * 0.01
                pDOP = (payload[OFFSET_DOP_PDOP] | (payload[OFFSET_DOP_PDOP + 1] << 8)) * 0.01
                tDOP = (payload[OFFSET_DOP_TDOP] | (payload[OFFSET_DOP_TDOP + 1] << 8)) * 0.01
                vDOP = (payload[OFFSET_DOP_VDOP] | (payload[OFFSET_DOP_VDOP + 1] << 8)) * 0.01
                hDOP = (payload[OFFSET_DOP_HDOP] | (payload[OFFSET_DOP_HDOP + 1] << 8)) * 0.01
                nDOP = (payload[OFFSET_DOP_NDOP] | (payload[OFFSET_DOP_NDOP + 1] << 8)) * 0.01
                eDOP = (payload[OFFSET_DOP_EDOP] | (payload[OFFSET_DOP_EDOP + 1] << 8)) * 0.01
                return f"DOP: G={gDOP:.2f} P={pDOP:.2f} T={tDOP:.2f} V={vDOP:.2f} H={hDOP:.2f}"
        elif self.msg_id == NAV_VELECEF:  # NAV-VELECEF
            if len(payload) >= 20:
                iTOW = payload[OFFSET_VELECEF_ITOW] | (payload[OFFSET_VELECEF_ITOW + 1] << 8) | \
                       (payload[OFFSET_VELECEF_ITOW + 2] << 16) | (payload[OFFSET_VELECEF_ITOW + 3] << 24)
                ecefVX = payload[OFFSET_VELECEF_ECEFVX] | (payload[OFFSET_VELECEF_ECEFVX + 1] << 8) | \
                        (payload[OFFSET_VELECEF_ECEFVX + 2] << 16) | (payload[OFFSET_VELECEF_ECEFVX + 3] << 24)
                ecefVY = payload[OFFSET_VELECEF_ECEFVY] | (payload[OFFSET_VELECEF_ECEFVY + 1] << 8) | \
                        (payload[OFFSET_VELECEF_ECEFVY + 2] << 16) | (payload[OFFSET_VELECEF_ECEFVY + 3] << 24)
                ecefVZ = payload[OFFSET_VELECEF_ECEFVZ] | (payload[OFFSET_VELECEF_ECEFVZ + 1] << 8) | \
                        (payload[OFFSET_VELECEF_ECEFVZ + 2] << 16) | (payload[OFFSET_VELECEF_ECEFVZ + 3] << 24)
                sAcc = payload[OFFSET_VELECEF_SACC] | (payload[OFFSET_VELECEF_SACC + 1] << 8) | \
                       (payload[OFFSET_VELECEF_SACC + 2] << 16) | (payload[OFFSET_VELECEF_SACC + 3] << 24)
                return f"ECEF Vel: X={ecefVX/100}m/s Y={ecefVY/100}m/s Z={ecefVZ/100}m/s (±{sAcc/100}m/s)"
        elif self.msg_id == NAV_VELNED:  # NAV-VELNED
            if len(payload) >= 36:
                iTOW = payload[OFFSET_VELNED_ITOW] | (payload[OFFSET_VELNED_ITOW + 1] << 8) | \
                       (payload[OFFSET_VELNED_ITOW + 2] << 16) | (payload[OFFSET_VELNED_ITOW + 3] << 24)
                velN = payload[OFFSET_VELNED_VELN] | (payload[OFFSET_VELNED_VELN + 1] << 8) | \
                       (payload[OFFSET_VELNED_VELN + 2] << 16) | (payload[OFFSET_VELNED_VELN + 3] << 24)
                velE = payload[OFFSET_VELNED_VELE] | (payload[OFFSET_VELNED_VELE + 1] << 8) | \
                       (payload[OFFSET_VELNED_VELE + 2] << 16) | (payload[OFFSET_VELNED_VELE + 3] << 24)
                velD = payload[OFFSET_VELNED_VELD] | (payload[OFFSET_VELNED_VELD + 1] << 8) | \
                       (payload[OFFSET_VELNED_VELD + 2] << 16) | (payload[OFFSET_VELNED_VELD + 3] << 24)
                speed = payload[OFFSET_VELNED_SPEED] | (payload[OFFSET_VELNED_SPEED + 1] << 8) | \
                        (payload[OFFSET_VELNED_SPEED + 2] << 16) | (payload[OFFSET_VELNED_SPEED + 3] << 24)
                gSpeed = payload[OFFSET_VELNED_GSPEED] | (payload[OFFSET_VELNED_GSPEED + 1] << 8) | \
                        (payload[OFFSET_VELNED_GSPEED + 2] << 16) | (payload[OFFSET_VELNED_GSPEED + 3] << 24)
                heading = payload[OFFSET_VELNED_HEADING] | (payload[OFFSET_VELNED_HEADING + 1] << 8) | \
                         (payload[OFFSET_VELNED_HEADING + 2] << 16) | (payload[OFFSET_VELNED_HEADING + 3] << 24)
                sAcc = payload[OFFSET_VELNED_SACC] | (payload[OFFSET_VELNED_SACC + 1] << 8) | \
                       (payload[OFFSET_VELNED_SACC + 2] << 16) | (payload[OFFSET_VELNED_SACC + 3] << 24)
                cAcc = payload[OFFSET_VELNED_CACC] | (payload[OFFSET_VELNED_CACC + 1] << 8) | \
                       (payload[OFFSET_VELNED_CACC + 2] << 16) | (payload[OFFSET_VELNED_CACC + 3] << 24)
                return f"NED Vel: N={velN/100}m/s E={velE/100}m/s D={velD/100}m/s Speed={speed/100}m/s Heading={heading*1e-5}°"
        elif self.msg_id == NAV_CLOCK:  # NAV-CLOCK
            if len(payload) >= 20:
                iTOW = payload[OFFSET_CLOCK_ITOW] | (payload[OFFSET_CLOCK_ITOW + 1] << 8) | \
                       (payload[OFFSET_CLOCK_ITOW + 2] << 16) | (payload[OFFSET_CLOCK_ITOW + 3] << 24)
                clkB = payload[OFFSET_CLOCK_BIAS] | (payload[OFFSET_CLOCK_BIAS + 1] << 8) | \
                      (payload[OFFSET_CLOCK_BIAS + 2] << 16) | (payload[OFFSET_CLOCK_BIAS + 3] << 24)
                clkD = payload[OFFSET_CLOCK_DRIFT] | (payload[OFFSET_CLOCK_DRIFT + 1] << 8) | \
                      (payload[OFFSET_CLOCK_DRIFT + 2] << 16) | (payload[OFFSET_CLOCK_DRIFT + 3] << 24)
                tAcc = payload[OFFSET_CLOCK_TACC] | (payload[OFFSET_CLOCK_TACC + 1] << 8) | \
                      (payload[OFFSET_CLOCK_TACC + 2] << 16) | (payload[OFFSET_CLOCK_TACC + 3] << 24)
                fAcc = payload[OFFSET_CLOCK_FACC] | (payload[OFFSET_CLOCK_FACC + 1] << 8) | \
                      (payload[OFFSET_CLOCK_FACC + 2] << 16) | (payload[OFFSET_CLOCK_FACC + 3] << 24)
                return f"Clock: Bias={clkB}ns Drift={clkD}ns/s tAcc={tAcc}ns fAcc={fAcc}ps/s"
        elif self.msg_id == NAV_TIMEGPS:  # NAV-TIMEGPS
            if len(payload) >= 16:
                iTOW = payload[OFFSET_TIMEGPS_ITOW] | (payload[OFFSET_TIMEGPS_ITOW + 1] << 8) | \
                       (payload[OFFSET_TIMEGPS_ITOW + 2] << 16) | (payload[OFFSET_TIMEGPS_ITOW + 3] << 24)
                fTOW = payload[OFFSET_TIMEGPS_FTOW] | (payload[OFFSET_TIMEGPS_FTOW + 1] << 8) | \
                       (payload[OFFSET_TIMEGPS_FTOW + 2] << 16) | (payload[OFFSET_TIMEGPS_FTOW + 3] << 24)
                week = payload[OFFSET_TIMEGPS_WEEK] | (payload[OFFSET_TIMEGPS_WEEK + 1] << 8)
                leapS = payload[OFFSET_TIMEGPS_LEAPS]
                valid = payload[OFFSET_TIMEGPS_VALID]
                tAcc = payload[OFFSET_TIMEGPS_TACC] | (payload[OFFSET_TIMEGPS_TACC + 1] << 8) | \
                       (payload[OFFSET_TIMEGPS_TACC + 2] << 16) | (payload[OFFSET_TIMEGPS_TACC + 3] << 24)
                return f"GPS Time: Week {week} TOW {iTOW}ms LeapS {leapS}s tAcc={tAcc}ns"
        elif self.msg_id == NAV_TIMEUTC:  # NAV-TIMEUTC
            if len(payload) >= 20:
                iTOW = payload[OFFSET_TIMEUTC_ITOW] | (payload[OFFSET_TIMEUTC_ITOW + 1] << 8) | \
                       (payload[OFFSET_TIMEUTC_ITOW + 2] << 16) | (payload[OFFSET_TIMEUTC_ITOW + 3] << 24)
                tAcc = payload[OFFSET_TIMEUTC_TACC] | (payload[OFFSET_TIMEUTC_TACC + 1] << 8) | \
                       (payload[OFFSET_TIMEUTC_TACC + 2] << 16) | (payload[OFFSET_TIMEUTC_TACC + 3] << 24)
                nano = payload[OFFSET_TIMEUTC_NANO] | (payload[OFFSET_TIMEUTC_NANO + 1] << 8) | \
                       (payload[OFFSET_TIMEUTC_NANO + 2] << 16) | (payload[OFFSET_TIMEUTC_NANO + 3] << 24)
                year = payload[OFFSET_TIMEUTC_YEAR] | (payload[OFFSET_TIMEUTC_YEAR + 1] << 8)
                month = payload[OFFSET_TIMEUTC_MONTH]
                day = payload[OFFSET_TIMEUTC_DAY]
                hour = payload[OFFSET_TIMEUTC_HOUR]
                min = payload[OFFSET_TIMEUTC_MIN]
                sec = payload[OFFSET_TIMEUTC_SEC]
                valid = payload[OFFSET_TIMEUTC_VALID]
                return f"UTC: {year}-{month:02d}-{day:02d} {hour:02d}:{min:02d}:{sec:02d}.{nano:09d}"
        elif self.msg_id == NAV_ODO:  # NAV-ODO
            if len(payload) >= 20:
                version = payload[OFFSET_ODO_VERSION]
                iTOW = payload[OFFSET_ODO_ITOW] | (payload[OFFSET_ODO_ITOW + 1] << 8) | \
                       (payload[OFFSET_ODO_ITOW + 2] << 16) | (payload[OFFSET_ODO_ITOW + 3] << 24)
                distance = payload[OFFSET_ODO_DISTANCE] | (payload[OFFSET_ODO_DISTANCE + 1] << 8) | \
                          (payload[OFFSET_ODO_DISTANCE + 2] << 16) | (payload[OFFSET_ODO_DISTANCE + 3] << 24)
                totalDistance = payload[OFFSET_ODO_TOTAL] | (payload[OFFSET_ODO_TOTAL + 1] << 8) | \
                              (payload[OFFSET_ODO_TOTAL + 2] << 16) | (payload[OFFSET_ODO_TOTAL + 3] << 24)
                distanceStd = payload[OFFSET_ODO_DISTANCESTD] | (payload[OFFSET_ODO_DISTANCESTD + 1] << 8) | \
                             (payload[OFFSET_ODO_DISTANCESTD + 2] << 16) | (payload[OFFSET_ODO_DISTANCESTD + 3] << 24)
                return f"ODO: Trip={distance}m Total={totalDistance}m (±{distanceStd}m)"
        elif self.msg_id == NAV_AOPSTATUS:  # NAV-AOPSTATUS
            if len(payload) >= 16:
                iTOW = payload[OFFSET_AOP_ITOW] | (payload[OFFSET_AOP_ITOW + 1] << 8) | \
                       (payload[OFFSET_AOP_ITOW + 2] << 16) | (payload[OFFSET_AOP_ITOW + 3] << 24)
                aopCfg = payload[OFFSET_AOP_CONFIG]
                status = payload[OFFSET_AOP_STATUS]
                return f"AOP Status: Config=0x{aopCfg:02X} Status=0x{status:02X}"
        
        # For unknown NAV messages, show raw bytes
        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"NAV-0x{self.msg_id:02X}: {payload_hex}"

    def parse_rxm_msg(self, payload):
        """Parse RXM class messages"""
        if len(payload) == 0:
            return "Poll receiver manager data"
            
        if self.msg_id == 0x02:  # RXM-RAW
            if len(payload) >= 8:
                rcvTow = struct.unpack('d', bytes(payload[OFFSET_RAW_RCVTOW:OFFSET_RAW_RCVTOW + 8]))[0]
                week = payload[OFFSET_RAW_WEEK] | (payload[OFFSET_RAW_WEEK + 1] << 8)
                numSV = payload[OFFSET_RAW_NUMSV]
                return f"Raw: Week {week}, SVs: {numSV}"
                
        elif self.msg_id == 0x10:  # RXM-RAWX
            if len(payload) >= 16:
                rcvTow = struct.unpack('d', bytes(payload[OFFSET_RAWX_RCVTOW:OFFSET_RAWX_RCVTOW + 8]))[0]
                week = payload[OFFSET_RAWX_WEEK] | (payload[OFFSET_RAWX_WEEK + 1] << 8)
                leapS = payload[OFFSET_RAWX_LEAPS]
                numMeas = payload[OFFSET_RAWX_NUMSV]
                recStat = payload[OFFSET_RAWX_RECSTAT]
                version = payload[OFFSET_RAWX_VERSION]
                return f"RawX: Week {week}, LeapS {leapS}, Measurements: {numMeas}, Status: 0x{recStat:02X}"
                
        elif self.msg_id == 0x15:  # RXM-SFRBX
            if len(payload) >= 8:
                gnssId = payload[OFFSET_SFRBX_GNSSID]
                svId = payload[OFFSET_SFRBX_SVID]
                freqId = payload[OFFSET_SFRBX_FREQID]
                numWords = payload[OFFSET_SFRBX_NUMWORDS]
                version = payload[OFFSET_SFRBX_VERSION]
                
                gnss_types = {
                    GNSS_GPS: "GPS",
                    GNSS_SBAS: "SBAS",
                    GNSS_GALILEO: "Galileo",
                    GNSS_BEIDOU: "BeiDou",
                    GNSS_IMES: "IMES",
                    GNSS_QZSS: "QZSS",
                    GNSS_GLONASS: "GLONASS"
                }
                gnss_name = gnss_types.get(gnssId, f"GNSS{gnssId}")
                
                return f"SFRBX: {gnss_name}-{svId} FreqId:{freqId} Words:{numWords}"

        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"RXM-0x{self.msg_id:02X}: {payload_hex}"

    def parse_inf_msg(self, payload):
        """Parse INF class messages"""
        if len(payload) > 0:
            try:
                # Try to decode as ASCII text
                text = bytes(payload).decode('ascii').rstrip('\0')
                return f"Info: {text}"
            except:
                pass
        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"INF-0x{self.msg_id:02X}: {payload_hex}"

    def parse_mon_msg(self, payload):
        """Parse MON class messages"""
        if len(payload) == 0:
            msg_names = {
                MON_IO: "IO",
                MON_VER: "VER",
                MON_MSGPP: "MSGPP",
                MON_RXBUF: "RXBUF",
                MON_TXBUF: "TXBUF",
                MON_HW: "HW",
                MON_HW2: "HW2"
            }
            msg_name = msg_names.get(self.msg_id, f"0x{self.msg_id:02X}")
            return f"Poll MON-{msg_name} status"
            
        if self.msg_id == MON_IO:  # MON-IO
            if len(payload) >= 20:
                rxBytes = payload[OFFSET_IO_RXBYTES] | (payload[OFFSET_IO_RXBYTES + 1] << 8) | \
                         (payload[OFFSET_IO_RXBYTES + 2] << 16) | (payload[OFFSET_IO_RXBYTES + 3] << 24)
                txBytes = payload[OFFSET_IO_TXBYTES] | (payload[OFFSET_IO_TXBYTES + 1] << 8) | \
                         (payload[OFFSET_IO_TXBYTES + 2] << 16) | (payload[OFFSET_IO_TXBYTES + 3] << 24)
                parityErrs = payload[OFFSET_IO_PARITYERRS] | (payload[OFFSET_IO_PARITYERRS + 1] << 8)
                framingErrs = payload[OFFSET_IO_FRAMINGERRS] | (payload[OFFSET_IO_FRAMINGERRS + 1] << 8)
                overrunErrs = payload[OFFSET_IO_OVERRUNERRS] | (payload[OFFSET_IO_OVERRUNERRS + 1] << 8)
                breakCond = payload[OFFSET_IO_BREAKCOND] | (payload[OFFSET_IO_BREAKCOND + 1] << 8)
                rxBusy = payload[OFFSET_IO_RXBUSY] | (payload[OFFSET_IO_RXBUSY + 1] << 8)
                txBusy = payload[OFFSET_IO_TXBUSY] | (payload[OFFSET_IO_TXBUSY + 1] << 8)
                return f"IO: RX={rxBytes} TX={txBytes} Errs={parityErrs}p,{framingErrs}f,{overrunErrs}o"
                
        elif self.msg_id == MON_MSGPP:  # MON-MSGPP
            if len(payload) >= 120:
                msg1 = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_MSGPP_MSG1, OFFSET_MSGPP_MSG2, 2)]
                msg2 = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_MSGPP_MSG2, OFFSET_MSGPP_MSG3, 2)]
                msg3 = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_MSGPP_MSG3, OFFSET_MSGPP_MSG4, 2)]
                msg4 = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_MSGPP_MSG4, OFFSET_MSGPP_MSG5, 2)]
                msg5 = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_MSGPP_MSG5, OFFSET_MSGPP_MSG6, 2)]
                msg6 = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_MSGPP_MSG6, OFFSET_MSGPP_SKIPPED, 2)]
                skipped = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_MSGPP_SKIPPED, OFFSET_MSGPP_SKIPPED+16, 2)]
                return f"MSGPP: Port1={sum(msg1)} Port2={sum(msg2)} Port3={sum(msg3)} Skipped={sum(skipped)}"
                
        elif self.msg_id == MON_RXBUF:  # MON-RXBUF
            if len(payload) >= 24:
                pending = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_RXBUF_PENDING, OFFSET_RXBUF_USAGE, 2)]
                usage = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_RXBUF_USAGE, OFFSET_RXBUF_PEAKUSAGE, 2)]
                return f"RXBUF: Usage={usage[0]}%,{usage[1]}%,{usage[2]}% Pending={pending[0]},{pending[1]},{pending[2]}"
                
        elif self.msg_id == MON_TXBUF:  # MON-TXBUF
            if len(payload) >= 28:
                pending = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_TXBUF_PENDING, OFFSET_TXBUF_USAGE, 2)]
                usage = [payload[i] | (payload[i+1] << 8) for i in range(OFFSET_TXBUF_USAGE, OFFSET_TXBUF_PEAKUSAGE, 2)]
                tUsage = payload[OFFSET_TXBUF_TUSAGE] | (payload[OFFSET_TXBUF_TUSAGE + 1] << 8)
                tPending = payload[OFFSET_TXBUF_TPENDING] | (payload[OFFSET_TXBUF_TPENDING + 1] << 8)
                return f"TXBUF: Usage={usage[0]}%,{usage[1]}%,{usage[2]}% Pending={pending[0]},{pending[1]},{pending[2]}"
                
        elif self.msg_id == MON_VER:  # MON-VER
            if len(payload) == 0:
                return "Poll version information"
            elif len(payload) >= 40:
                try:
                    # Fixed length fields
                    sw_version = bytes(payload[0:30]).decode('ascii').rstrip('\0')
                    hw_version = bytes(payload[30:40]).decode('ascii').rstrip('\0')
                    
                    # Parse extension fields (repeated blocks of 30 bytes)
                    extensions = []
                    offset = 40
                    while offset + 30 <= len(payload):
                        ext = bytes(payload[offset:offset+30]).decode('ascii').rstrip('\0')
                        if ext:
                            extensions.append(ext)
                        offset += 30
                    
                    # Format the output
                    result = f"VER: SW={sw_version} HW={hw_version}"
                    if extensions:
                        result += f" [{'; '.join(extensions)}]"
                    return result
                except:
                    return "VER: Invalid version string"
                    
        elif self.msg_id == MON_HW2:  # MON-HW2
            if len(payload) >= 28:
                ofsI = payload[OFFSET_HW2_OFSI]
                magI = payload[OFFSET_HW2_MAGNI]
                ofsQ = payload[OFFSET_HW2_OFSQ]
                magQ = payload[OFFSET_HW2_MAGNQ]
                cfgSource = payload[OFFSET_HW2_CFGSRC]
                postStatus = payload[OFFSET_HW2_POSTSTATUS]
                return f"HW2: I(ofs={ofsI},mag={magI}) Q(ofs={ofsQ},mag={magQ}) Cfg={cfgSource}"
        
        # For unknown MON messages, show raw bytes
        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"MON-0x{self.msg_id:02X}: {payload_hex}"

    def parse_tim_msg(self, payload):
        """Parse TIM class messages"""
        if len(payload) == 0:
            msg_names = {
                TIM_SVIN: "SVIN",
                TIM_VRFY: "VRFY",
                TIM_DOSC: "DOSC",
                TIM_TOS: "TOS",
                TIM_SMEAS: "SMEAS"
            }
            msg_name = msg_names.get(self.msg_id, f"0x{self.msg_id:02X}")
            return f"Poll TIM-{msg_name} timing data"
            
        if self.msg_id == TIM_SVIN:  # TIM-SVIN
            if len(payload) >= 28:
                dur = payload[OFFSET_SVIN_DUR] | (payload[OFFSET_SVIN_DUR + 1] << 8) | \
                      (payload[OFFSET_SVIN_DUR + 2] << 16) | (payload[OFFSET_SVIN_DUR + 3] << 24)
                meanX = payload[OFFSET_SVIN_MEANX] | (payload[OFFSET_SVIN_MEANX + 1] << 8) | \
                       (payload[OFFSET_SVIN_MEANX + 2] << 16) | (payload[OFFSET_SVIN_MEANX + 3] << 24)
                meanY = payload[OFFSET_SVIN_MEANY] | (payload[OFFSET_SVIN_MEANY + 1] << 8) | \
                       (payload[OFFSET_SVIN_MEANY + 2] << 16) | (payload[OFFSET_SVIN_MEANY + 3] << 24)
                meanZ = payload[OFFSET_SVIN_MEANZ] | (payload[OFFSET_SVIN_MEANZ + 1] << 8) | \
                       (payload[OFFSET_SVIN_MEANZ + 2] << 16) | (payload[OFFSET_SVIN_MEANZ + 3] << 24)
                meanV = payload[OFFSET_SVIN_MEANV] | (payload[OFFSET_SVIN_MEANV + 1] << 8) | \
                       (payload[OFFSET_SVIN_MEANV + 2] << 16) | (payload[OFFSET_SVIN_MEANV + 3] << 24)
                obs = payload[OFFSET_SVIN_OBS] | (payload[OFFSET_SVIN_OBS + 1] << 8) | \
                      (payload[OFFSET_SVIN_OBS + 2] << 16) | (payload[OFFSET_SVIN_OBS + 3] << 24)
                valid = payload[OFFSET_SVIN_VALID]
                active = payload[OFFSET_SVIN_ACTIVE]
                return f"SVIN: Active={active} Valid={valid} Dur={dur}s Obs={obs}"
                
        elif self.msg_id == TIM_VRFY:  # TIM-VRFY
            if len(payload) >= 20:
                itow = payload[OFFSET_TP_TOWMS] | (payload[OFFSET_TP_TOWMS + 1] << 8) | \
                       (payload[OFFSET_TP_TOWMS + 2] << 16) | (payload[OFFSET_TP_TOWMS + 3] << 24)
                frac = payload[OFFSET_TP_TOWSUB] | (payload[OFFSET_TP_TOWSUB + 1] << 8) | \
                       (payload[OFFSET_TP_TOWSUB + 2] << 16) | (payload[OFFSET_TP_TOWSUB + 3] << 24)
                deltaMs = payload[OFFSET_TP_QERR] | (payload[OFFSET_TP_QERR + 1] << 8) | \
                         (payload[OFFSET_TP_QERR + 2] << 16) | (payload[OFFSET_TP_QERR + 3] << 24)
                deltaNs = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                wno = payload[OFFSET_TP_WEEK] | (payload[OFFSET_TP_WEEK + 1] << 8)
                flags = payload[OFFSET_TP_FLAGS]
                return f"VRFY: Week={wno} Delta={deltaMs}ms+{deltaNs}ns Flags=0x{flags:02X}"
                
        elif self.msg_id == TIM_DOSC:  # TIM-DOSC
            if len(payload) >= 8:
                version = payload[0]
                value = payload[2] | (payload[3] << 8)
                freq = payload[4] | (payload[5] << 8)
                return f"DOSC: Value={value} Freq={freq}"
                
        elif self.msg_id == TIM_TOS:  # TIM-TOS
            if len(payload) >= 56:
                version = payload[OFFSET_TOS_VERSION]
                gnssId = payload[OFFSET_TOS_GNSSID]
                flags = payload[OFFSET_TOS_FLAGS]
                year = payload[OFFSET_TOS_YEAR] | (payload[OFFSET_TOS_YEAR + 1] << 8)
                month = payload[OFFSET_TOS_MONTH]
                day = payload[OFFSET_TOS_DAY]
                hour = payload[OFFSET_TOS_HOUR]
                minute = payload[OFFSET_TOS_MINUTE]
                second = payload[OFFSET_TOS_SECOND]
                subInt = payload[OFFSET_TOS_SUBINT] | (payload[OFFSET_TOS_SUBINT + 1] << 8) | \
                        (payload[OFFSET_TOS_SUBINT + 2] << 16) | (payload[OFFSET_TOS_SUBINT + 3] << 24)
                intLen = payload[OFFSET_TOS_INTLEN] | (payload[OFFSET_TOS_INTLEN + 1] << 8) | \
                        (payload[OFFSET_TOS_INTLEN + 2] << 16) | (payload[OFFSET_TOS_INTLEN + 3] << 24)
                intStat = payload[OFFSET_TOS_INTSTAT]
                slope = payload[OFFSET_TOS_SLOPE] | (payload[OFFSET_TOS_SLOPE + 1] << 8) | \
                        (payload[OFFSET_TOS_SLOPE + 2] << 16) | (payload[OFFSET_TOS_SLOPE + 3] << 24)
                hpm = payload[OFFSET_TOS_HPM] | (payload[OFFSET_TOS_HPM + 1] << 8) | \
                      (payload[OFFSET_TOS_HPM + 2] << 16) | (payload[OFFSET_TOS_HPM + 3] << 24)
                return f"TOS: {year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d} IntStat={intStat} HPM={hpm}"
                
        elif self.msg_id == TIM_SMEAS:  # TIM-SMEAS
            if len(payload) >= 12:
                version = payload[OFFSET_SMEAS_VERSION]
                flags = payload[OFFSET_SMEAS_FLAGS]
                period = payload[OFFSET_SMEAS_PERIOD] | (payload[OFFSET_SMEAS_PERIOD + 1] << 8) | \
                        (payload[OFFSET_SMEAS_PERIOD + 2] << 16) | (payload[OFFSET_SMEAS_PERIOD + 3] << 24)
                intOsc = payload[OFFSET_SMEAS_INTOSC] | (payload[OFFSET_SMEAS_INTOSC + 1] << 8)
                extOsc = payload[OFFSET_SMEAS_EXTOSC] | (payload[OFFSET_SMEAS_EXTOSC + 1] << 8)
                return f"SMEAS: Period={period} IntOsc={intOsc} ExtOsc={extOsc} Flags=0x{flags:02X}"
        
        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"TIM-0x{self.msg_id:02X}: {payload_hex}"

    def parse_log_msg(self, payload):
        """Parse LOG class messages"""
        if len(payload) == 0:
            msg_names = {
                LOG_ERASE: "ERASE",
                LOG_STRING: "STRING",
                LOG_CREATE: "CREATE",
                LOG_INFO: "INFO",
                LOG_RETRIEVE: "RETRIEVE"
            }
            msg_name = msg_names.get(self.msg_id, f"0x{self.msg_id:02X}")
            return f"Poll LOG-{msg_name} logging data"
            
        if self.msg_id == LOG_CREATE:  # LOG-CREATE
            if len(payload) >= 8:
                version = payload[OFFSET_CREATE_VERSION]
                logCfg = payload[OFFSET_CREATE_LOGCFG]
                logSize = payload[OFFSET_CREATE_LOGSIZE]
                userType = payload[OFFSET_CREATE_USERTYPE]
                year = payload[5] | (payload[6] << 8)
                month = payload[7]
                return f"CREATE: Size={logSize} Type={userType} Date={year}-{month:02d}"
                
        elif self.msg_id == LOG_ERASE:  # LOG-ERASE
            return "ERASE"
            
        elif self.msg_id == LOG_INFO:  # LOG-INFO
            if len(payload) >= 48:
                version = payload[OFFSET_INFO_VERSION]
                filestoreCapacity = payload[OFFSET_INFO_CAPACITY] | (payload[OFFSET_INFO_CAPACITY + 1] << 8) | \
                                  (payload[OFFSET_INFO_CAPACITY + 2] << 16) | (payload[OFFSET_INFO_CAPACITY + 3] << 24)
                currentMaxLogSize = payload[OFFSET_INFO_MAXSIZE] | (payload[OFFSET_INFO_MAXSIZE + 1] << 8) | \
                                  (payload[OFFSET_INFO_MAXSIZE + 2] << 16) | (payload[OFFSET_INFO_MAXSIZE + 3] << 24)
                currentLogSize = payload[OFFSET_INFO_CURSIZE] | (payload[OFFSET_INFO_CURSIZE + 1] << 8) | \
                               (payload[OFFSET_INFO_CURSIZE + 2] << 16) | (payload[OFFSET_INFO_CURSIZE + 3] << 24)
                entryCount = payload[OFFSET_INFO_ENTRIES] | (payload[OFFSET_INFO_ENTRIES + 1] << 8) | \
                            (payload[OFFSET_INFO_ENTRIES + 2] << 16) | (payload[OFFSET_INFO_ENTRIES + 3] << 24)
                oldestYear = payload[OFFSET_INFO_OLDESTYR] | (payload[OFFSET_INFO_OLDESTYR + 1] << 8)
                oldestMonth = payload[OFFSET_INFO_OLDESTMON]
                oldestDay = payload[OFFSET_INFO_OLDESTDAY]
                oldestHour = payload[OFFSET_INFO_OLDESTHR]
                oldestMinute = payload[OFFSET_INFO_OLDESTMIN]
                oldestSecond = payload[OFFSET_INFO_OLDESTSEC]
                newestYear = payload[OFFSET_INFO_NEWESTYR] | (payload[OFFSET_INFO_NEWESTYR + 1] << 8)
                newestMonth = payload[OFFSET_INFO_NEWESTMON]
                newestDay = payload[OFFSET_INFO_NEWESTDAY]
                newestHour = payload[OFFSET_INFO_NEWESTHR]
                newestMinute = payload[OFFSET_INFO_NEWESTMIN]
                newestSecond = payload[OFFSET_INFO_NEWESTSEC]
                return f"INFO: Entries={entryCount} Size={currentLogSize}/{currentMaxLogSize} Latest={newestYear}-{newestMonth:02d}-{newestDay:02d}"
                
        elif self.msg_id == LOG_RETRIEVE:  # LOG-RETRIEVE
            if len(payload) >= 12:
                startNumber = payload[OFFSET_RETRIEVE_START] | (payload[OFFSET_RETRIEVE_START + 1] << 8) | \
                            (payload[OFFSET_RETRIEVE_START + 2] << 16) | (payload[OFFSET_RETRIEVE_START + 3] << 24)
                entryCount = payload[OFFSET_RETRIEVE_COUNT] | (payload[OFFSET_RETRIEVE_COUNT + 1] << 8) | \
                            (payload[OFFSET_RETRIEVE_COUNT + 2] << 16) | (payload[OFFSET_RETRIEVE_COUNT + 3] << 24)
                version = payload[OFFSET_RETRIEVE_VERSION]
                return f"RETRIEVE: Start={startNumber} Count={entryCount}"
                
        elif self.msg_id == LOG_STRING:  # LOG-STRING
            if len(payload) > 0:
                try:
                    text = bytes(payload).decode('ascii').rstrip('\0')
                    return f"STRING: {text}"
                except:
                    return f"STRING: {len(payload)} bytes"
            return "STRING: empty"
            
        return f"LOG-0x{self.msg_id:02X}: {' '.join([f'0x{b:02X}' for b in payload])}"

    def get_message_description(self):
        """Return a human-readable description of the UBX message"""
        class_descriptions = {
            CLASS_NAV: "NAV",
            CLASS_RXM: "RXM",
            CLASS_INF: "INF",
            CLASS_ACK: "ACK",
            CLASS_CFG: "CFG",
            CLASS_UPD: "UPD",
            CLASS_MON: "MON",
            CLASS_TIM: "TIM",
            CLASS_MGA: "MGA",
            CLASS_LOG: "LOG",
            CLASS_SEC: "SEC",
            CLASS_HNR: "HNR"
        }
        
        class_name = class_descriptions.get(self.msg_class, f"Unknown(0x{self.msg_class:02X})")
        
        # Parse specific message types
        details = ""
        
        if self.msg_class == CLASS_NAV:  # NAV
            details = self.parse_nav_msg(self.payload)
        elif self.msg_class == CLASS_RXM:  # RXM
            details = self.parse_rxm_msg(self.payload)
        elif self.msg_class == CLASS_INF:  # INF
            details = self.parse_inf_msg(self.payload)
        elif self.msg_class == CLASS_ACK:  # ACK
            details = self.parse_ack_msg(self.payload)
        elif self.msg_class == CLASS_CFG:  # CFG
            details = self.parse_cfg_msg(self.payload)
        elif self.msg_class == CLASS_MON:  # MON
            details = self.parse_mon_msg(self.payload)
        elif self.msg_class == CLASS_TIM:  # TIM
            details = self.parse_tim_msg(self.payload)
        elif self.msg_class == CLASS_LOG:  # LOG
            details = self.parse_log_msg(self.payload)
            
        if not details:
            # For unknown messages, just show the payload bytes
            payload_hex = ' '.join([f'0x{b:02X}' for b in self.payload])
            details = f"Payload: {payload_hex}"
            
        return {
            'class_name': class_name,
            'msg_id': f"0x{self.msg_id:02X}",
            'length': str(len(self.payload)),
            'details': details
        }

    def calculate_checksum(self, data, initial_values=(0,0)):
        """Calculate UBX checksum for the given data"""
        ck_a, ck_b = initial_values
        for byte in data:
            ck_a = (ck_a + byte) & 0xFF
            ck_b = (ck_b + ck_a) & 0xFF
        return ck_a, ck_b

    def decode(self, frame):
        """Process each byte of the UBX protocol"""
        # Handle different possible frame data formats
        if isinstance(frame.data, dict):
            data = frame.data.get('data')
            if isinstance(data, bytes) and len(data) == 1:
                byte = data[0]
            elif isinstance(data, list) and len(data) == 1:
                byte = data[0]
            elif isinstance(data, int):
                byte = data
            else:
                return None
        elif isinstance(frame.data, (int, bytes)):
            byte = frame.data if isinstance(frame.data, int) else frame.data[0]
        else:
            return None

        if self.state == State.SYNC_CHAR1:
            if byte == SYNC1:
                self.reset_state()
                self.state = State.SYNC_CHAR2
                self.frame_start_time = frame.start_time
            return None

        elif self.state == State.SYNC_CHAR2:
            if byte == SYNC2:
                self.state = State.CLASS
            else:
                self.state = State.SYNC_CHAR1
            return None

        elif self.state == State.CLASS:
            self.msg_class = byte
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([self.msg_class])
            self.state = State.ID
            return None

        elif self.state == State.ID:
            self.msg_id = byte
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([self.msg_id], (self.calc_ck_a, self.calc_ck_b))
            self.state = State.LENGTH_LSB
            return None

        elif self.state == State.LENGTH_LSB:
            self.length = byte
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([self.length], (self.calc_ck_a, self.calc_ck_b))
            self.state = State.LENGTH_MSB
            return None

        elif self.state == State.LENGTH_MSB:
            self.length |= (byte << 8)
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([byte], (self.calc_ck_a, self.calc_ck_b))
            self.state = State.PAYLOAD if self.length > 0 else State.CK_A
            return None

        elif self.state == State.PAYLOAD:
            self.payload.append(byte)
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([byte], (self.calc_ck_a, self.calc_ck_b))
            
            if len(self.payload) == self.length:
                self.state = State.CK_A
            return None

        elif self.state == State.CK_A:
            self.ck_a = byte
            self.state = State.CK_B
            return None

        elif self.state == State.CK_B:
            self.ck_b = byte
            self.state = State.SYNC_CHAR1

            # Verify checksum
            if self.ck_a == self.calc_ck_a and self.ck_b == self.calc_ck_b:
                desc = self.get_message_description()
                return AnalyzerFrame('ubx_frame', self.frame_start_time, frame.end_time, {
                    'description': f"{desc['class_name']}-{desc['msg_id']}: {desc['details']}",
                    'class_name': desc['class_name'],
                    'msg_id': desc['msg_id'],
                    'length': desc['length'],
                    'details': desc['details']
                })
            else:
                return AnalyzerFrame('ubx_error', self.frame_start_time, frame.end_time, {
                    'error': f'Checksum mismatch (calc: {self.calc_ck_a:02X},{self.calc_ck_b:02X} recv: {self.ck_a:02X},{self.ck_b:02X})'
                })

        return None 