from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import struct

# UBX Protocol States
class State:
    SYNC_CHAR1 = 0  # Looking for 0xB5
    SYNC_CHAR2 = 1  # Looking for 0x62
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
        },
        'debug': {
            'format': 'Debug: {{data.message}}'
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
        iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
        year = payload[4] | (payload[5] << 8)
        month = payload[6]
        day = payload[7]
        hour = payload[8]
        min = payload[9]
        sec = payload[10]
        valid = payload[11]
        fixType = payload[20]
        flags = payload[21]
        numSV = payload[23]
        lon = payload[24] | (payload[25] << 8) | (payload[26] << 16) | (payload[27] << 24)
        lat = payload[28] | (payload[29] << 8) | (payload[30] << 16) | (payload[31] << 24)
        height = payload[32] | (payload[33] << 8) | (payload[34] << 16) | (payload[35] << 24)
        hMSL = payload[36] | (payload[37] << 8) | (payload[38] << 16) | (payload[39] << 24)
        
        # Convert lat/lon to degrees
        lat_deg = lat * 1e-7
        lon_deg = lon * 1e-7
        
        # Determine fix type string
        fix_types = {
            0: "No Fix",
            1: "Dead Reckoning",
            2: "2D Fix",
            3: "3D Fix",
            4: "GNSS + Dead Reckoning",
            5: "Time only"
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
        if self.msg_id == 0x00:  # CFG-PRT
            if len(payload) >= 20:
                portID = payload[0]
                reserved1 = payload[1]
                txReady = payload[2] | (payload[3] << 8)
                mode = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                baudRate = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                inProtoMask = payload[12] | (payload[13] << 8)
                outProtoMask = payload[14] | (payload[15] << 8)
                flags = payload[16] | (payload[17] << 8)
                reserved2 = payload[18] | (payload[19] << 8)
                port_types = {0: "DDC", 1: "UART1", 2: "UART2", 3: "USB", 4: "SPI"}
                port_name = port_types.get(portID, f"Port{portID}")
                return f"PRT: {port_name} Baud={baudRate} In=0x{inProtoMask:04X} Out=0x{outProtoMask:04X}"
        elif self.msg_id == 0x13:  # CFG-ANT
            if len(payload) >= 4:
                flags = payload[0] | (payload[1] << 8)
                pins = payload[2] | (payload[3] << 8)
                return f"ANT: Flags=0x{flags:04X} Pins=0x{pins:04X}"
        elif self.msg_id == 0x32:  # CFG-PM
            if len(payload) >= 24:
                version = payload[0]
                reserved1 = payload[1]
                reserved2 = payload[2]
                reserved3 = payload[3]
                flags = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                updatePeriod = payload[8] | (payload[9] << 8)
                searchPeriod = payload[10] | (payload[11] << 8)
                gridOffset = payload[12] | (payload[13] << 8)
                onTime = payload[14] | (payload[15] << 8)
                minAcqTime = payload[16] | (payload[17] << 8)
                return f"PM: Update={updatePeriod}ms Search={searchPeriod}ms OnTime={onTime}s Flags=0x{flags:08X}"
        elif self.msg_id == 0x34:  # CFG-RINV
            if len(payload) >= 1:
                flags = payload[0]
                data = bytes(payload[1:]).decode('ascii').rstrip('\0') if len(payload) > 1 else ""
                return f"RINV: Flags=0x{flags:02X} Data='{data}'"
        elif self.msg_id == 0x39:  # CFG-ITFM
            if len(payload) >= 8:
                config = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                config2 = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                return f"ITFM: Config=0x{config:08X} Config2=0x{config2:08X}"
        elif self.msg_id == 0x47:  # CFG-LOGFILTER
            if len(payload) >= 12:
                version = payload[0]
                flags = payload[4] | (payload[5] << 8)
                minInterval = payload[6] | (payload[7] << 8)
                timeThreshold = payload[8] | (payload[9] << 8)
                speedThreshold = payload[10] | (payload[11] << 8)
                return f"LOGFILTER: MinInt={minInterval}s TimeThresh={timeThreshold}s SpeedThresh={speedThreshold}m/s"
        elif self.msg_id == 0x1D:  # CFG-TMODE
            if len(payload) >= 28:
                timeMode = payload[0]
                reserved1 = payload[1]
                flags = payload[2] | (payload[3] << 8)
                ecefX = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                ecefY = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                ecefZ = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                mode_str = "Disabled" if timeMode == 0 else "Survey In" if timeMode == 1 else "Fixed"
                return f"TMODE: Mode={mode_str} Pos=({ecefX},{ecefY},{ecefZ})"
        elif self.msg_id == 0x16:  # CFG-SBAS
            if len(payload) >= 8:
                mode = payload[0]
                usage = payload[1]
                maxSBAS = payload[2]
                scanmode2 = payload[3]
                scanmode1 = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                
                enabled = (mode & 0x01) != 0
                test = (mode & 0x02) != 0
                
                use_bits = []
                if usage & 0x01: use_bits.append("Range")
                if usage & 0x02: use_bits.append("Diff")
                if usage & 0x04: use_bits.append("Integrity")
                
                return f"SBAS: {'En' if enabled else 'Dis'} Test:{'Y' if test else 'N'} Max:{maxSBAS} Use:{'+'.join(use_bits) if use_bits else 'None'}"
                
        elif self.msg_id == 0x01:  # CFG-MSG
            if len(payload) == 3:
                msg_class = payload[0]
                msg_id = payload[1]
                rate = payload[2]
                
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
                msg_class_name = class_descriptions.get(msg_class, f"Unknown(0x{msg_class:02X})")
                msg_names = {
                    (0x01, 0x07): "PVT",
                    (0x01, 0x35): "SAT",
                    (0x01, 0x03): "STATUS",
                    (0x06, 0x01): "MSG",
                    (0x06, 0x3E): "GNSS",
                    (0x0A, 0x04): "VER",
                    (0x06, 0x24): "NAV5",
                    (0x06, 0x86): "USB",
                    (0x06, 0x16): "SBAS"
                }
                msg_name = msg_names.get((msg_class, msg_id), f"0x{msg_id:02X}")
                return f"Configure {msg_class_name}-{msg_name} rate: {rate}Hz"
                
        elif self.msg_id == 0x24 or self.msg_id == 0x06:  # CFG-NAV5 (both 0x24 and 0x06 are used)
            if len(payload) >= 36:
                mask = payload[0] | (payload[1] << 8)
                dyn_model = payload[2]
                fix_mode = payload[3]
                fixed_alt = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                fixed_alt_var = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                min_elev = payload[12]
                dr_limit = payload[13]
                pdop = (payload[14] | (payload[15] << 8)) * 0.1
                tdop = (payload[16] | (payload[17] << 8)) * 0.1
                pacc = payload[18] | (payload[19] << 8)
                tacc = payload[20] | (payload[21] << 8)
                static_hold_thresh = payload[22]
                dgps_timeout = payload[23]
                cnoThreshNumSVs = payload[24]
                cnoThresh = payload[25]
                
                dyn_models = {
                    0: "Portable",
                    2: "Stationary",
                    3: "Pedestrian",
                    4: "Automotive",
                    5: "Sea",
                    6: "Airborne <1g",
                    7: "Airborne <2g",
                    8: "Airborne <4g",
                    9: "Wrist Worn"
                }
                
                fix_modes = {
                    1: "2D only",
                    2: "3D only",
                    3: "Auto 2D/3D"
                }
                
                model = dyn_models.get(dyn_model, f"Unknown ({dyn_model})")
                mode = fix_modes.get(fix_mode, f"Unknown ({fix_mode})")
                
                return (f"Model:{model} Mode:{mode} MinElev:{min_elev}° "
                       f"PDOP:{pdop:.1f} TDOP:{tdop:.1f} "
                       f"CNO:{cnoThresh}dB/{cnoThreshNumSVs}SVs")
                
        elif self.msg_id == 0x08:  # CFG-RATE
            if len(payload) >= 6:
                meas_rate = payload[0] | (payload[1] << 8)
                nav_rate = payload[2] | (payload[3] << 8)
                time_ref = payload[4] | (payload[5] << 8)
                
                time_refs = {
                    0: "UTC",
                    1: "GPS",
                    2: "GLONASS",
                    3: "BeiDou",
                    4: "Galileo"
                }
                
                ref = time_refs.get(time_ref, f"Unknown ({time_ref})")
                return f"Measurement Rate: {meas_rate}ms, Navigation Rate: {nav_rate} cycles, Time Reference: {ref}"
                
        elif self.msg_id == 0x3E:  # CFG-GNSS
            if len(payload) >= 4:
                version = payload[0]
                numTrkChHw = payload[1]
                numTrkChUse = payload[2]
                numConfigBlocks = payload[3]
                
                configs = []
                offset = 4
                for i in range(numConfigBlocks):
                    if offset + 8 <= len(payload):
                        gnssId = payload[offset]
                        resTrkCh = payload[offset + 1]
                        maxTrkCh = payload[offset + 2]
                        reserved1 = payload[offset + 3]
                        flags = payload[offset + 4] | (payload[offset + 5] << 8) | \
                               (payload[offset + 6] << 16) | (payload[offset + 7] << 24)
                        
                        enabled = (flags & 0x01) != 0
                        
                        gnss_types = {
                            0: "GPS", 1: "SBAS", 2: "Galileo", 3: "BeiDou",
                            4: "IMES", 5: "QZSS", 6: "GLONASS"
                        }
                        gnss_name = gnss_types.get(gnssId, f"GNSS{gnssId}")
                        
                        configs.append(f"{gnss_name}({'En' if enabled else 'Dis'},{maxTrkCh}ch)")
                        offset += 8
                
                return f"GNSS Config: {', '.join(configs)}"
        
        elif self.msg_id == 0x86:  # CFG-USB
            if len(payload) >= 108:
                vendorID = payload[0] | (payload[1] << 8)
                productID = payload[2] | (payload[3] << 8)
                reserved1 = payload[4] | (payload[5] << 8)
                reserved2 = payload[6] | (payload[7] << 8)
                powerConsumption = payload[8] | (payload[9] << 8)
                flags = payload[10] | (payload[11] << 8)
                
                # Check if this is a poll request (all zeros)
                if all(b == 0 for b in payload):
                    return "Poll USB configuration"
                
                # Get null-terminated strings
                try:
                    vendor_str = bytes(payload[12:40]).decode('ascii').rstrip('\0')
                    product_str = bytes(payload[40:68]).decode('ascii').rstrip('\0')
                    serial_str = bytes(payload[68:96]).decode('ascii').rstrip('\0')
                    
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
        
        # For other CFG messages or unknown formats, show raw bytes but with better formatting
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
        if self.msg_id == 0x35:  # NAV-SAT
            if len(payload) >= 8:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                version = payload[4]
                numSvs = payload[5]
                reserved = payload[6:8]
                
                sats = []
                offset = 8
                for i in range(numSvs):
                    if offset + 12 <= len(payload):
                        gnssId = payload[offset]
                        svId = payload[offset + 1]
                        cno = payload[offset + 2]  # Carrier to noise ratio
                        elev = payload[offset + 3]  # Elevation in degrees
                        azim = payload[offset + 4] | (payload[offset + 5] << 8)  # Azimuth in degrees
                        prRes = payload[offset + 6] | (payload[offset + 7] << 8)  # Pseudo range residual
                        flags = payload[offset + 8] | (payload[offset + 9] << 8) | \
                               (payload[offset + 10] << 16) | (payload[offset + 11] << 24)
                        
                        quality = (flags >> 4) & 7
                        used = (flags & 0x08) != 0
                        health = (flags >> 7) & 3
                        
                        gnss_types = {
                            0: "GPS", 1: "SBAS", 2: "Galileo", 3: "BeiDou",
                            4: "IMES", 5: "QZSS", 6: "GLONASS"
                        }
                        gnss_name = gnss_types.get(gnssId, f"GNSS{gnssId}")
                        
                        sat_info = f"{gnss_name}-{svId}({cno}dB)"
                        if used:
                            sat_info += "*"  # Mark used satellites
                        sats.append(sat_info)
                        
                        offset += 12
                
                # Group satellites by system and sort by signal strength
                return f"Sats({numSvs}): {', '.join(sats)}"
        
        elif self.msg_id == 0x07:  # NAV-PVT
            return self.parse_nav_pvt(payload)
        elif self.msg_id == 0x03:  # NAV-STATUS
            return self.parse_nav_status(payload)
        elif self.msg_id == 0x01:  # NAV-POSECEF
            if len(payload) >= 20:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                ecefX = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                ecefY = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                ecefZ = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                pAcc = payload[16] | (payload[17] << 8) | (payload[18] << 16) | (payload[19] << 24)
                return f"ECEF: X={ecefX/100}m Y={ecefY/100}m Z={ecefZ/100}m (±{pAcc/100}m)"
        elif self.msg_id == 0x02:  # NAV-POSLLH
            if len(payload) >= 28:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                lon = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                lat = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                height = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                hMSL = payload[16] | (payload[17] << 8) | (payload[18] << 16) | (payload[19] << 24)
                hAcc = payload[20] | (payload[21] << 8) | (payload[22] << 16) | (payload[23] << 24)
                vAcc = payload[24] | (payload[25] << 8) | (payload[26] << 16) | (payload[27] << 24)
                return f"Pos: {lat*1e-7}°, {lon*1e-7}°, Alt: {hMSL/1000}m (±H:{hAcc/1000}m V:{vAcc/1000}m)"
        elif self.msg_id == 0x04:  # NAV-DOP
            if len(payload) >= 18:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                gDOP = (payload[4] | (payload[5] << 8)) * 0.01
                pDOP = (payload[6] | (payload[7] << 8)) * 0.01
                tDOP = (payload[8] | (payload[9] << 8)) * 0.01
                vDOP = (payload[10] | (payload[11] << 8)) * 0.01
                hDOP = (payload[12] | (payload[13] << 8)) * 0.01
                nDOP = (payload[14] | (payload[15] << 8)) * 0.01
                eDOP = (payload[16] | (payload[17] << 8)) * 0.01
                return f"DOP: G={gDOP:.2f} P={pDOP:.2f} T={tDOP:.2f} V={vDOP:.2f} H={hDOP:.2f}"
        elif self.msg_id == 0x22:  # NAV-CLOCK
            if len(payload) >= 20:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                clkB = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                clkD = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                tAcc = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                fAcc = payload[16] | (payload[17] << 8) | (payload[18] << 16) | (payload[19] << 24)
                return f"Clock: Bias={clkB}ns Drift={clkD}ns/s tAcc={tAcc}ns fAcc={fAcc}ps/s"
        elif self.msg_id == 0x20:  # NAV-TIMEGPS
            if len(payload) >= 16:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                fTOW = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                week = payload[8] | (payload[9] << 8)
                leapS = payload[10]
                valid = payload[11]
                tAcc = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                return f"GPS Time: Week {week} TOW {iTOW}ms LeapS {leapS}s tAcc={tAcc}ns"
        elif self.msg_id == 0x21:  # NAV-TIMEUTC
            if len(payload) >= 20:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                tAcc = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                nano = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                year = payload[12] | (payload[13] << 8)
                month = payload[14]
                day = payload[15]
                hour = payload[16]
                min = payload[17]
                sec = payload[18]
                valid = payload[19]
                return f"UTC: {year}-{month:02d}-{day:02d} {hour:02d}:{min:02d}:{sec:02d}.{nano:09d}"
        elif self.msg_id == 0x11:  # NAV-VELECEF
            if len(payload) >= 20:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                ecefVX = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                ecefVY = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                ecefVZ = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                sAcc = payload[16] | (payload[17] << 8) | (payload[18] << 16) | (payload[19] << 24)
                return f"ECEF Vel: X={ecefVX/100}m/s Y={ecefVY/100}m/s Z={ecefVZ/100}m/s (±{sAcc/100}m/s)"
        elif self.msg_id == 0x12:  # NAV-VELNED
            if len(payload) >= 36:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                velN = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                velE = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                velD = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                speed = payload[16] | (payload[17] << 8) | (payload[18] << 16) | (payload[19] << 24)
                gSpeed = payload[20] | (payload[21] << 8) | (payload[22] << 16) | (payload[23] << 24)
                heading = payload[24] | (payload[25] << 8) | (payload[26] << 16) | (payload[27] << 24)
                sAcc = payload[28] | (payload[29] << 8) | (payload[30] << 16) | (payload[31] << 24)
                cAcc = payload[32] | (payload[33] << 8) | (payload[34] << 16) | (payload[35] << 24)
                return f"NED Vel: N={velN/100}m/s E={velE/100}m/s D={velD/100}m/s Speed={speed/100}m/s Heading={heading*1e-5}°"
        elif self.msg_id == 0x60:  # NAV-AOPSTATUS
            if len(payload) >= 16:
                iTOW = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                aopCfg = payload[4]
                status = payload[5]
                return f"AOP Status: Config=0x{aopCfg:02X} Status=0x{status:02X}"
        elif self.msg_id == 0x09:  # NAV-ODO
            if len(payload) >= 20:
                version = payload[0]
                iTOW = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                distance = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                totalDistance = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                distanceStd = payload[16] | (payload[17] << 8) | (payload[18] << 16) | (payload[19] << 24)
                return f"ODO: Trip={distance}m Total={totalDistance}m (±{distanceStd}m)"
        
        # For unknown NAV messages, show raw bytes
        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"NAV-0x{self.msg_id:02X}: {payload_hex}"

    def parse_rxm_msg(self, payload):
        """Parse RXM class messages"""
        if self.msg_id == 0x02:  # RXM-RAW
            if len(payload) >= 8:
                rcvTow = struct.unpack('d', bytes(payload[0:8]))[0]
                week = payload[8] | (payload[9] << 8)
                numSV = payload[10]
                return f"Raw: Week {week}, SVs: {numSV}"
        elif self.msg_id == 0x10:  # RXM-RAWX
            if len(payload) >= 16:
                rcvTow = struct.unpack('d', bytes(payload[0:8]))[0]
                week = payload[8] | (payload[9] << 8)
                numMeas = payload[11]
                recStat = payload[12]
                return f"RawX: Week {week}, Measurements: {numMeas}"
        elif self.msg_id == 0x15:  # RXM-SFRBX
            if len(payload) >= 8:
                gnssId = payload[0]
                svId = payload[1]
                freqId = payload[2]
                numWords = payload[3]
                return f"SFRBX: GNSS:{gnssId} SV:{svId} Words:{numWords}"
                
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
        if self.msg_id == 0x09:  # MON-HW
            if len(payload) >= 60:
                pinSel = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                pinBank = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                pinDir = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                pinVal = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                noisePerMS = payload[16] | (payload[17] << 8)
                agcCnt = payload[18] | (payload[19] << 8)
                aStatus = payload[20]
                aPower = payload[21]
                flags = payload[22]
                reserved1 = payload[23]
                usedMask = payload[24] | (payload[25] << 8) | (payload[26] << 16) | (payload[27] << 24)
                VP = [payload[28+i] for i in range(17)]
                jamInd = payload[45]
                reserved2 = payload[46] | (payload[47] << 8)
                pinIrq = payload[48] | (payload[49] << 8) | (payload[50] << 16) | (payload[51] << 24)
                pullH = payload[52] | (payload[53] << 8) | (payload[54] << 16) | (payload[55] << 24)
                pullL = payload[56] | (payload[57] << 8) | (payload[58] << 16) | (payload[59] << 24)
                return f"HW: Noise={noisePerMS}/ms AGC={agcCnt} Jam={jamInd} Ant={aStatus}"
        elif self.msg_id == 0x02:  # MON-IO
            if len(payload) >= 20:
                rxBytes = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                txBytes = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                parityErrs = payload[8] | (payload[9] << 8)
                framingErrs = payload[10] | (payload[11] << 8)
                overrunErrs = payload[12] | (payload[13] << 8)
                breakCond = payload[14] | (payload[15] << 8)
                rxBusy = payload[16] | (payload[17] << 8)
                txBusy = payload[18] | (payload[19] << 8)
                return f"IO: RX={rxBytes} TX={txBytes} Errs={parityErrs}p,{framingErrs}f,{overrunErrs}o"
        elif self.msg_id == 0x06:  # MON-MSGPP
            if len(payload) >= 120:
                msg1 = [payload[i] | (payload[i+1] << 8) for i in range(0, 16, 2)]
                msg2 = [payload[i] | (payload[i+1] << 8) for i in range(16, 32, 2)]
                msg3 = [payload[i] | (payload[i+1] << 8) for i in range(32, 48, 2)]
                msg4 = [payload[i] | (payload[i+1] << 8) for i in range(48, 64, 2)]
                msg5 = [payload[i] | (payload[i+1] << 8) for i in range(64, 80, 2)]
                msg6 = [payload[i] | (payload[i+1] << 8) for i in range(80, 96, 2)]
                skipped = [payload[i] | (payload[i+1] << 8) for i in range(96, 112, 2)]
                return f"MSGPP: Port1={sum(msg1)} Port2={sum(msg2)} Port3={sum(msg3)} Skipped={sum(skipped)}"
        elif self.msg_id == 0x07:  # MON-RXBUF
            if len(payload) >= 24:
                pending = [payload[i] | (payload[i+1] << 8) for i in range(0, 12, 2)]
                usage = [payload[i] | (payload[i+1] << 8) for i in range(12, 24, 2)]
                return f"RXBUF: Usage={usage[0]}%,{usage[1]}%,{usage[2]}% Pending={pending[0]},{pending[1]},{pending[2]}"
        elif self.msg_id == 0x08:  # MON-TXBUF
            if len(payload) >= 28:
                pending = [payload[i] | (payload[i+1] << 8) for i in range(0, 12, 2)]
                usage = [payload[i] | (payload[i+1] << 8) for i in range(12, 24, 2)]
                tUsage = payload[24] | (payload[25] << 8)
                tPending = payload[26] | (payload[27] << 8)
                return f"TXBUF: Usage={usage[0]}%,{usage[1]}%,{usage[2]}% Pending={pending[0]},{pending[1]},{pending[2]}"
        elif self.msg_id == 0x0B:  # MON-HW2
            if len(payload) >= 28:
                ofsI = payload[0]
                magI = payload[1]
                ofsQ = payload[2]
                magQ = payload[3]
                cfgSource = payload[4]
                reserved1 = [payload[i] for i in range(5, 24)]
                postStatus = payload[24]
                reserved2 = [payload[i] for i in range(25, 28)]
                return f"HW2: I(ofs={ofsI},mag={magI}) Q(ofs={ofsQ},mag={magQ}) Cfg={cfgSource}"
        
        # For unknown MON messages, show raw bytes
        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"MON-0x{self.msg_id:02X}: {payload_hex}"

    def parse_tim_msg(self, payload):
        """Parse TIM class messages"""
        if self.msg_id == 0x04:  # TIM-SVIN
            if len(payload) >= 28:
                dur = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                meanX = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                meanY = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                meanZ = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                meanV = payload[16] | (payload[17] << 8) | (payload[18] << 16) | (payload[19] << 24)
                obs = payload[20] | (payload[21] << 8) | (payload[22] << 16) | (payload[23] << 24)
                valid = payload[24]
                active = payload[25]
                return f"SVIN: Active={active} Valid={valid} Dur={dur}s Obs={obs}"
        elif self.msg_id == 0x06:  # TIM-VRFY
            if len(payload) >= 20:
                itow = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                frac = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                deltaMs = payload[8] | (payload[9] << 8) | (payload[10] << 16) | (payload[11] << 24)
                deltaNs = payload[12] | (payload[13] << 8) | (payload[14] << 16) | (payload[15] << 24)
                wno = payload[16] | (payload[17] << 8)
                flags = payload[18]
                reserved1 = payload[19]
                return f"VRFY: Week={wno} Delta={deltaMs}ms+{deltaNs}ns Flags=0x{flags:02X}"
        elif self.msg_id == 0x11:  # TIM-DOSC
            if len(payload) >= 8:
                version = payload[0]
                reserved1 = payload[1]
                value = payload[2] | (payload[3] << 8)
                freq = payload[4] | (payload[5] << 8)
                reserved2 = payload[6] | (payload[7] << 8)
                return f"DOSC: Value={value} Freq={freq}"
        elif self.msg_id == 0x12:  # TIM-TOS
            if len(payload) >= 56:
                version = payload[0]
                gnssId = payload[1]
                reserved1 = payload[2]
                flags = payload[3]
                year = payload[4] | (payload[5] << 8)
                month = payload[6]
                day = payload[7]
                hour = payload[8]
                minute = payload[9]
                second = payload[10]
                return f"TOS: {year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
        elif self.msg_id == 0x13:  # TIM-SMEAS
            if len(payload) >= 12:
                version = payload[0]
                reserved1 = payload[1]
                reserved2 = payload[2]
                flags = payload[3]
                period = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                intOsc = payload[8] | (payload[9] << 8)
                extOsc = payload[10] | (payload[11] << 8)
                return f"SMEAS: Period={period} IntOsc={intOsc} ExtOsc={extOsc}"
        
        payload_hex = ' '.join([f'0x{b:02X}' for b in payload])
        return f"TIM-0x{self.msg_id:02X}: {payload_hex}"

    def parse_log_msg(self, payload):
        """Parse LOG class messages"""
        if self.msg_id == 0x07:  # LOG-CREATE
            if len(payload) >= 8:
                version = payload[0]
                logCfg = payload[1]
                reserved1 = payload[2]
                logSize = payload[3]
                userType = payload[4]
                year = payload[5] | (payload[6] << 8)
                month = payload[7]
                return f"CREATE: Size={logSize} Type={userType} Date={year}-{month:02d}"
        elif self.msg_id == 0x03:  # LOG-ERASE
            return "ERASE"
        elif self.msg_id == 0x08:  # LOG-INFO
            if len(payload) >= 48:
                version = payload[0]
                reserved1 = payload[1]
                filestoreCapacity = payload[2] | (payload[3] << 8) | (payload[4] << 16) | (payload[5] << 24)
                reserved2 = payload[6] | (payload[7] << 8) | (payload[8] << 16) | (payload[9] << 24)
                currentMaxLogSize = payload[10] | (payload[11] << 8) | (payload[12] << 16) | (payload[13] << 24)
                currentLogSize = payload[14] | (payload[15] << 8) | (payload[16] << 16) | (payload[17] << 24)
                entryCount = payload[18] | (payload[19] << 8) | (payload[20] << 16) | (payload[21] << 24)
                oldestYear = payload[22] | (payload[23] << 8)
                oldestMonth = payload[24]
                oldestDay = payload[25]
                oldestHour = payload[26]
                oldestMinute = payload[27]
                oldestSecond = payload[28]
                newestYear = payload[34] | (payload[35] << 8)
                newestMonth = payload[36]
                newestDay = payload[37]
                newestHour = payload[38]
                newestMinute = payload[39]
                newestSecond = payload[40]
                return f"INFO: Entries={entryCount} Size={currentLogSize}/{currentMaxLogSize} Latest={newestYear}-{newestMonth:02d}-{newestDay:02d}"
        elif self.msg_id == 0x09:  # LOG-RETRIEVE
            if len(payload) >= 12:
                startNumber = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24)
                entryCount = payload[4] | (payload[5] << 8) | (payload[6] << 16) | (payload[7] << 24)
                version = payload[8]
                reserved1 = payload[9]
                reserved2 = payload[10]
                reserved3 = payload[11]
                return f"RETRIEVE: Start={startNumber} Count={entryCount}"
        elif self.msg_id == 0x04:  # LOG-STRING
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
        
        class_name = class_descriptions.get(self.msg_class, f"Unknown(0x{self.msg_class:02X})")
        
        # Parse specific message types
        details = ""
        raw_bytes = self.format_raw_bytes()
        
        if self.msg_class == 0x01:  # NAV
            details = self.parse_nav_msg(self.payload)
        elif self.msg_class == 0x02:  # RXM
            details = self.parse_rxm_msg(self.payload)
        elif self.msg_class == 0x04:  # INF
            details = self.parse_inf_msg(self.payload)
        elif self.msg_class == 0x05:  # ACK
            details = self.parse_ack_msg(self.payload)
        elif self.msg_class == 0x06:  # CFG
            details = self.parse_cfg_msg(self.payload)
        elif self.msg_class == 0x0A:  # MON
            details = self.parse_mon_msg(self.payload)
        elif self.msg_class == 0x0D:  # TIM
            details = self.parse_tim_msg(self.payload)
        elif self.msg_class == 0x21:  # LOG
            details = self.parse_log_msg(self.payload)
            
        if not details:
            # For unknown messages, just show the payload bytes
            payload_hex = ' '.join([f'0x{b:02X}' for b in self.payload])
            details = f"Payload: {payload_hex}"
            
        return {
            'class_name': class_name,
            'msg_id': f"0x{self.msg_id:02X}",
            'length': str(len(self.payload)),
            'details': details,
            'raw_bytes': raw_bytes
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
        try:
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
                    print(f"Unexpected frame data format: {frame.data}")
                    return AnalyzerFrame('debug', frame.start_time, frame.end_time, {
                        'message': f'Unexpected frame data format: {frame.data}'
                    })
            elif isinstance(frame.data, (int, bytes)):
                byte = frame.data if isinstance(frame.data, int) else frame.data[0]
            else:
                print(f"Unsupported frame data type: {type(frame.data)}")
                return AnalyzerFrame('debug', frame.start_time, frame.end_time, {
                    'message': f'Unsupported frame data type: {type(frame.data)}'
                })
                
            print(f"Got byte: 0x{byte:02X}, current state: {self.state}")
            
        except Exception as e:
            print(f"Error processing frame data: {e}")
            return AnalyzerFrame('debug', frame.start_time, frame.end_time, {
                'message': f'Error processing frame: {str(e)}'
            })

        if self.state == State.SYNC_CHAR1:
            if byte == 0xB5:
                print("Found SYNC1 (0xB5)")
                self.reset_state()
                self.state = State.SYNC_CHAR2
                self.frame_start_time = frame.start_time
            return None

        elif self.state == State.SYNC_CHAR2:
            if byte == 0x62:
                print("Found SYNC2 (0x62)")
                self.state = State.CLASS
            else:
                print(f"Invalid SYNC2: 0x{byte:02X}, resetting")
                self.state = State.SYNC_CHAR1
            return None

        elif self.state == State.CLASS:
            self.msg_class = byte
            print(f"Got message class: 0x{self.msg_class:02X}")
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([self.msg_class])
            print(f"Checksum after class: A=0x{self.calc_ck_a:02X}, B=0x{self.calc_ck_b:02X}")
            self.state = State.ID
            return None

        elif self.state == State.ID:
            self.msg_id = byte
            print(f"Got message ID: 0x{self.msg_id:02X}")
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([self.msg_id], (self.calc_ck_a, self.calc_ck_b))
            print(f"Checksum after ID: A=0x{self.calc_ck_a:02X}, B=0x{self.calc_ck_b:02X}")
            self.state = State.LENGTH_LSB
            return None

        elif self.state == State.LENGTH_LSB:
            self.length = byte
            print(f"Got length LSB: 0x{byte:02X}")
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([self.length], (self.calc_ck_a, self.calc_ck_b))
            print(f"Checksum after len_lsb: A=0x{self.calc_ck_a:02X}, B=0x{self.calc_ck_b:02X}")
            self.state = State.LENGTH_MSB
            return None

        elif self.state == State.LENGTH_MSB:
            self.length |= (byte << 8)
            print(f"Got length MSB: 0x{byte:02X}, total length: {self.length}")
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([byte], (self.calc_ck_a, self.calc_ck_b))
            print(f"Checksum after len_msb: A=0x{self.calc_ck_a:02X}, B=0x{self.calc_ck_b:02X}")
            self.state = State.PAYLOAD if self.length > 0 else State.CK_A
            return None

        elif self.state == State.PAYLOAD:
            self.payload.append(byte)
            print(f"Got payload byte: 0x{byte:02X}, {len(self.payload)}/{self.length}")
            self.calc_ck_a, self.calc_ck_b = self.calculate_checksum([byte], (self.calc_ck_a, self.calc_ck_b))
            print(f"Checksum after payload byte: A=0x{self.calc_ck_a:02X}, B=0x{self.calc_ck_b:02X}")
            
            if len(self.payload) == self.length:
                print("Payload complete")
                self.state = State.CK_A
            return None

        elif self.state == State.CK_A:
            self.ck_a = byte
            print(f"Got checksum A: 0x{self.ck_a:02X}")
            self.state = State.CK_B
            return None

        elif self.state == State.CK_B:
            self.ck_b = byte
            print(f"Got checksum B: 0x{self.ck_b:02X}")
            print(f"Calculated checksums: A=0x{self.calc_ck_a:02X}, B=0x{self.calc_ck_b:02X}")
            self.state = State.SYNC_CHAR1

            # Verify checksum
            if self.ck_a == self.calc_ck_a and self.ck_b == self.calc_ck_b:
                desc = self.get_message_description()
                print(f"Message complete and valid: {desc['class_name']}-{desc['msg_id']} ({desc['length']} bytes)")
                print(f"Raw bytes: {desc['raw_bytes']}")
                return AnalyzerFrame('ubx_frame', self.frame_start_time, frame.end_time, {
                    'description': f"{desc['class_name']}-{desc['msg_id']}: {desc['details']}",
                    'class_name': desc['class_name'],
                    'msg_id': desc['msg_id'],
                    'length': desc['length'],
                    'details': f"{desc['details']} | Raw: {desc['raw_bytes']}"
                })
            else:
                print(f"Checksum mismatch! Calc: {self.calc_ck_a:02X},{self.calc_ck_b:02X} Recv: {self.ck_a:02X},{self.ck_b:02X}")
                return AnalyzerFrame('ubx_error', self.frame_start_time, frame.end_time, {
                    'error': f'Checksum mismatch (calc: {self.calc_ck_a:02X},{self.calc_ck_b:02X} recv: {self.ck_a:02X},{self.ck_b:02X})'
                })

        return None 