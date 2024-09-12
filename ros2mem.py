import logging
import os
import struct
import re
from typing import List, Tuple, Iterator, Optional
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements

vollog = logging.getLogger(__name__)


class ROS2Mem(interfaces.plugins.PluginInterface):
    """Searches for ROS2 artifacts, including RTPS patterns and network information, in memory dumps"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.URIRequirement(name="memory_file", description="Path to the memory dump file", optional=True),
        ]

    def run(self):
        return renderers.TreeGrid([("Output", str)], self._generator())

    def _generator(self):
        memory_file = self.config.get('memory_file') or self._context.config.get('automagic.LayerStacker.single_location')

        if not memory_file:
            vollog.error("Memory file path not provided")
            return

        file_path = memory_file.replace('file://', '')

        if not os.path.exists(file_path):
            vollog.error(f"Memory file not found: {file_path}")
            return

        file_size = os.path.getsize(file_path)
        vollog.info(f"Analyzing memory file: {file_path}")
        pattern = b'RTPS'
        chunk_size = 1024 * 1024  # 1MB chunks for more efficient reading

        try:
            with open(file_path, 'rb') as f:
                for chunk, offset in self._read_chunks(f, chunk_size):
                    yield from self._process_chunk(chunk, offset, pattern)
        except Exception as e:
            vollog.error(f"Error during memory search: {str(e)}")

    @staticmethod
    def _read_chunks(file, chunk_size: int) -> Iterator[Tuple[bytes, int]]:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            yield chunk, file.tell() - len(chunk)

    def _process_chunk(self, chunk: bytes, offset: int, pattern: bytes) -> Iterator[Tuple[int, Tuple[str]]]:
        for match in self._find_pattern(chunk, pattern):
            if match >= 42:
                data = chunk[match - 42:]  # Get from 42 bytes before RTPS to the end of chunk
                parsed_data, payload = self._parse_packet(data)
                if parsed_data:
                    decoded_payload = self._decode_payload(payload)
                    output = (f"(Offset) {hex(offset + match - 42)}, "
                              f"(MAC) {parsed_data[0]} >> {parsed_data[1]}, "
                              f"(IP) {parsed_data[2]}:{parsed_data[4]} >> {parsed_data[3]}:{parsed_data[5]}, "
                              f"(Payload) {decoded_payload}")
                    yield (0, (output,))

        # Scan for ROS2-specific keywords (rr/, rq/, rt/) in appropriate context
        # Additional keywords can be added to the 'keywords' list below to extend the search
        keywords = [b'rr/', b'rq/', b'rt/']
        for keyword in keywords:
            for match in re.finditer(re.escape(keyword), chunk):
                keyword_pos = match.start()
                keyword_end = match.end()

                if keyword_pos == 0 or chunk[keyword_pos - 1] == 0:
                    extracted_data = self._extract_data(chunk, keyword_end, max_length=50)

                    if len(extracted_data) <= 2 or not self._is_valid_data(extracted_data):
                        continue

                    if keyword == b'rt/':
                        type_ = 'ROS-Topic'
                    else:
                        type_ = 'Response' if keyword == b'rr/' else 'Request'

                    output = f"(Offset) {hex(offset + keyword_pos)}, (Type) {type_}, {extracted_data}"
                    yield (0, (output,))

    @staticmethod
    def _extract_data(chunk: bytes, start: int, max_length: int = 50) -> str:
        end = start + max_length
        data = chunk[start:end]
        try:
            string_end = next((i for i, byte in enumerate(data) if byte == 0 or byte > 127), len(data))
            data = data[:string_end]

            for encoding in ['utf-8', 'ascii', 'latin-1', 'cp1252']:
                try:
                    return data.decode(encoding).strip()
                except UnicodeDecodeError:
                    continue

            return data.hex()
        except Exception as e:
            vollog.debug(f"Error extracting data: {str(e)}")
            return f"ERROR: {str(e)}"

    @staticmethod
    def _is_valid_data(data: str) -> bool:
        return bool(re.match(r'^[a-zA-Z0-9_/.]+$', data))

    @staticmethod
    def _find_pattern(data: bytes, pattern: bytes):
        pattern_len = len(pattern)
        return (i for i in range(len(data) - pattern_len + 1) if data[i:i + pattern_len] == pattern)

    @staticmethod
    def _parse_packet(data: bytes) -> Tuple[Optional[Tuple[str, str, str, str, str, str]], bytes]:
        try:
            src_mac = ':'.join([f'{b:02x}' for b in data[:6]])
            dest_mac = ':'.join([f'{b:02x}' for b in data[6:12]])

            # Check IPv4 packet
            if data[12:14] == b'\x08\x00':
                src_ip = '.'.join([str(b) for b in data[26:30]])
                dest_ip = '.'.join([str(b) for b in data[30:34]])
                src_port, dest_port = struct.unpack('>HH', data[34:38])

                # Extract RTPS payload
                rtps_start = 42
                rtps_header = data[rtps_start:rtps_start + 4]
                if rtps_header == b'RTPS':
                    data_submessage_start = data.find(b'\x15\x05', rtps_start)
                    if data_submessage_start != -1:
                        submsg_length = struct.unpack('<H', data[data_submessage_start + 2:data_submessage_start + 4])[
                            0]
                        payload_start = data_submessage_start + 4
                        payload_end = payload_start + submsg_length
                        payload = data[payload_start:payload_end]
                    else:
                        payload = b"Data submessage not found"
                else:
                    payload = b"Not an RTPS packet"

                return (src_mac, dest_mac, src_ip, dest_ip, str(src_port), str(dest_port)), payload
            return None, b''
        except Exception as e:
            vollog.debug(f"Error parsing packet: {str(e)}")
            return None, b''

    @staticmethod
    def _decode_payload(payload: bytes, max_length: int = 100) -> str:
        try:
            for encoding in ['utf-8', 'ascii', 'latin-1', 'cp1252']:
                try:
                    decoded = payload.decode(encoding)
                    printable = ''.join(char if char.isprintable() or char.isspace() else ' ' for char in decoded)
                    printable = re.sub(r'\s+', ' ', printable).strip()
                    if len(printable) > max_length:
                        return f"{printable[:max_length]}... ({len(payload)} bytes)"
                    return printable
                except UnicodeDecodeError:
                    continue

            if len(payload) > max_length:
                return f"{payload[:max_length].hex()}... ({len(payload)} bytes)"
            return payload.hex()
        except Exception as e:
            return f"Error decoding payload: {str(e)}"
