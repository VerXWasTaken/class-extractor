#!/usr/bin/env python3
import os
import struct
import logging
from pathlib import Path
from typing import Optional, BinaryIO
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class JavaClassExtractor:
    MAGIC_NUMBER = b'\xCA\xFE\xBA\xBE'
    CHUNK_SIZE = 1024 * 1024
    MIN_CLASS_SIZE = 100
    MAX_CLASS_SIZE = 10 * 1024 * 1024
    VALID_MAJOR_VERSIONS = list(range(45, 66))
    
    def __init__(self, dump_file: str, output_dir: str = "extracted_classes"):
        self.dump_file = dump_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.class_count = 0
        self.cafebabe_count = 0
        self.log_file = self.output_dir / "extraction_log.txt"
        self.extracted_hashes = set()
        
    def extract_classes(self):
        logger.info(f"Starting extraction from: {self.dump_file}")
        logger.info(f"Output directory: {self.output_dir}")
        with open(self.dump_file, 'rb') as f:
            file_size = os.path.getsize(self.dump_file)
            logger.info(f"Memory dump size: {file_size:,} bytes")
            with open(self.log_file, 'w') as log:
                log.write("Offset,Size,Filename,Version,Hash\n")
                self._scan_file(f, log, file_size)
        logger.info(f"Extraction complete. Found {self.cafebabe_count} CAFEBABE signatures")
        logger.info(f"Successfully extracted {self.class_count} unique classes")
        
    def _scan_file(self, f: BinaryIO, log: BinaryIO, file_size: int):
        f.seek(0)
        data = f.read()
        offset = 0
        while True:
            idx = data.find(self.MAGIC_NUMBER, offset)
            if idx == -1:
                break
            self.cafebabe_count += 1
            if self._extract_class_from_memory(data, idx, log):
                self.class_count += 1
            offset = idx + 1
            if self.cafebabe_count % 10 == 0:
                logger.info(f"Processed {self.cafebabe_count} CAFEBABE signatures, extracted {self.class_count} classes")
    
    def _extract_class_from_memory(self, data: bytes, offset: int, log: BinaryIO) -> bool:
        try:
            if offset + 8 > len(data):
                return False
            if data[offset:offset+4] != self.MAGIC_NUMBER:
                return False
            minor_version = struct.unpack('>H', data[offset+4:offset+6])[0]
            major_version = struct.unpack('>H', data[offset+6:offset+8])[0]
            if major_version not in self.VALID_MAJOR_VERSIONS:
                return self._extract_class_heuristic(data, offset, log)
            class_size = self._calculate_class_size_from_memory(data, offset)
            if class_size is None:
                return self._extract_class_heuristic(data, offset, log)
            if class_size < self.MIN_CLASS_SIZE or class_size > self.MAX_CLASS_SIZE:
                return self._extract_class_heuristic(data, offset, log)
            if offset + class_size > len(data):
                return self._extract_class_heuristic(data, offset, log)
            class_data = data[offset:offset + class_size]
            if not class_data.startswith(self.MAGIC_NUMBER):
                return False
            class_hash = hashlib.md5(class_data).hexdigest()
            if class_hash in self.extracted_hashes:
                return False
            self.extracted_hashes.add(class_hash)
            filename = f"Class_{self.class_count + 1:05d}.class"
            output_path = self.output_dir / filename
            with open(output_path, 'wb') as out:
                out.write(class_data)
            with open(output_path, 'rb') as verify:
                if verify.read(4) != self.MAGIC_NUMBER:
                    os.remove(output_path)
                    return False
            log.write(f"{offset},{class_size},{filename},{major_version}.{minor_version},{class_hash}\n")
            logger.info(f"Extracted: {filename} (offset: {offset}, size: {class_size}, version: {major_version}.{minor_version})")
            return True
        except Exception as e:
            return self._extract_class_heuristic(data, offset, log)
    
    def _extract_class_heuristic(self, data: bytes, offset: int, log: BinaryIO) -> bool:
        try:
            next_cafebabe = data.find(self.MAGIC_NUMBER, offset + 4)
            possible_sizes = []
            if next_cafebabe != -1 and next_cafebabe - offset < self.MAX_CLASS_SIZE:
                possible_sizes.append(next_cafebabe - offset)
            zero_run_pos = offset + self.MIN_CLASS_SIZE
            while zero_run_pos < min(offset + self.MAX_CLASS_SIZE, len(data) - 8):
                if data[zero_run_pos:zero_run_pos + 8] == b'\x00' * 8:
                    possible_sizes.append(zero_run_pos - offset)
                    break
                zero_run_pos += 1
            common_sizes = [1024, 2048, 4096, 8192, 16384, 32768, 65536]
            for size in common_sizes:
                if offset + size <= len(data):
                    possible_sizes.append(size)
            for size in sorted(set(possible_sizes)):
                if size < self.MIN_CLASS_SIZE or size > self.MAX_CLASS_SIZE:
                    continue
                if offset + size > len(data):
                    continue
                class_data = data[offset:offset + size]
                if not class_data.startswith(self.MAGIC_NUMBER):
                    continue
                if len(class_data) >= 8:
                    minor_version = struct.unpack('>H', class_data[4:6])[0]
                    major_version = struct.unpack('>H', class_data[6:8])[0]
                    class_hash = hashlib.md5(class_data).hexdigest()
                    if class_hash in self.extracted_hashes:
                        continue
                    self.extracted_hashes.add(class_hash)
                    filename = f"Class_{self.class_count + 1:05d}_heuristic.class"
                    output_path = self.output_dir / filename
                    with open(output_path, 'wb') as out:
                        out.write(class_data)
                    version_str = f"{major_version}.{minor_version}" if major_version in self.VALID_MAJOR_VERSIONS else "unknown"
                    log.write(f"{offset},{size},{filename},{version_str},{class_hash}\n")
                    logger.info(f"Extracted (heuristic): {filename} (offset: {offset}, size: {size})")
                    return True
            if offset + 4096 <= len(data):
                class_data = data[offset:offset + 4096]
                if class_data.startswith(self.MAGIC_NUMBER):
                    class_hash = hashlib.md5(class_data).hexdigest()
                    if class_hash not in self.extracted_hashes:
                        self.extracted_hashes.add(class_hash)
                        filename = f"Class_{self.class_count + 1:05d}_chunk.class"
                        output_path = self.output_dir / filename
                        with open(output_path, 'wb') as out:
                            out.write(class_data)
                        log.write(f"{offset},4096,{filename},unknown,{class_hash}\n")
                        logger.info(f"Extracted (chunk): {filename} (offset: {offset}, size: 4096)")
                        return True
            return False
        except Exception as e:
            return False
    
    def _calculate_class_size_from_memory(self, data: bytes, start_offset: int) -> Optional[int]:
        try:
            offset = start_offset + 8
            if offset + 2 > len(data):
                return None
            constant_pool_count = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            if constant_pool_count == 0 or constant_pool_count > 65535:
                return None
            for i in range(1, constant_pool_count):
                if offset >= len(data):
                    return None
                tag = data[offset]
                offset += 1
                if tag == 1:
                    if offset + 2 > len(data):
                        return None
                    length = struct.unpack('>H', data[offset:offset+2])[0]
                    offset += 2 + length
                elif tag in [3, 4]:
                    offset += 4
                elif tag in [5, 6]:
                    offset += 8
                    i += 1
                elif tag in [7, 8]:
                    offset += 2
                elif tag in [9, 10, 11, 12]:
                    offset += 4
                elif tag == 15:
                    offset += 3
                elif tag == 16:
                    offset += 2
                elif tag == 18:
                    offset += 4
                elif tag in [19, 20]:
                    offset += 2
                else:
                    return None
                if offset - start_offset > self.MAX_CLASS_SIZE:
                    return None
            offset += 6
            if offset + 2 > len(data):
                return None
            interfaces_count = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2 + (interfaces_count * 2)
            if offset + 2 > len(data):
                return None
            fields_count = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            for _ in range(fields_count):
                offset += 6
                if offset + 2 > len(data):
                    return None
                attributes_count = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                offset = self._skip_attributes_in_memory(data, offset, attributes_count)
                if offset is None:
                    return None
            if offset + 2 > len(data):
                return None
            methods_count = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            for _ in range(methods_count):
                offset += 6
                if offset + 2 > len(data):
                    return None
                attributes_count = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                offset = self._skip_attributes_in_memory(data, offset, attributes_count)
                if offset is None:
                    return None
            if offset + 2 > len(data):
                return None
            attributes_count = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            offset = self._skip_attributes_in_memory(data, offset, attributes_count)
            if offset is None:
                return None
            return offset - start_offset
        except Exception as e:
            return None
    
    def _skip_attributes_in_memory(self, data: bytes, offset: int, count: int) -> Optional[int]:
        try:
            for _ in range(count):
                if offset + 6 > len(data):
                    return None
                offset += 2
                attribute_length = struct.unpack('>I', data[offset:offset+4])[0]
                offset += 4 + attribute_length
                if attribute_length > self.MAX_CLASS_SIZE:
                    return None
            return offset
        except:
            return None

def verify_class_files(directory: str):
    dir_path = Path(directory)
    total = 0
    valid = 0
    for class_file in dir_path.glob("*.class"):
        total += 1
        with open(class_file, 'rb') as f:
            magic = f.read(4)
            if magic == b'\xCA\xFE\xBA\xBE':
                valid += 1
            else:
                logger.warning(f"Invalid class file (no CAFEBABE): {class_file.name}")
    logger.info(f"Verification: {valid}/{total} files have valid CAFEBABE header")
    return valid, total

def analyze_dump_for_patterns(dump_file: str, sample_size: int = 10):
    logger.info("Analyzing dump file patterns...")
    with open(dump_file, 'rb') as f:
        data = f.read()
    magic = b'\xCA\xFE\xBA\xBE'
    occurrences = []
    offset = 0
    while len(occurrences) < sample_size:
        idx = data.find(magic, offset)
        if idx == -1:
            break
        occurrences.append(idx)
        offset = idx + 1
    logger.info(f"Found {len(occurrences)} CAFEBABE occurrences (showing first {sample_size})")
    for i, pos in enumerate(occurrences[:sample_size]):
        start = max(0, pos - 16)
        end = min(len(data), pos + 32)
        context = data[start:end]
        version_str = "unknown"
        if pos + 8 <= len(data):
            minor = struct.unpack('>H', data[pos+4:pos+6])[0]
            major = struct.unpack('>H', data[pos+6:pos+8])[0]
            version_str = f"{major}.{minor}"
        logger.info(f"CAFEBABE #{i+1} at offset {pos} (version: {version_str})")
        logger.info(f"  Context: {context.hex()}")
        if pos >= 4:
            before = data[pos-4:pos]
            logger.info(f"  Before: {before.hex()}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Extract Java classes from memory dump')
    parser.add_argument('dump_file', help='Path to memory dump file')
    parser.add_argument('-o', '--output', default='extracted_classes', help='Output directory (default: extracted_classes)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-a', '--analyze', action='store_true', help='Analyze dump patterns before extraction')
    parser.add_argument('--verify-only', action='store_true', help='Only verify existing extracted files')
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.verify_only:
        if os.path.exists(args.output):
            verify_class_files(args.output)
        else:
            logger.error(f"Output directory not found: {args.output}")
        return 0
    if not os.path.exists(args.dump_file):
        logger.error(f"Dump file not found: {args.dump_file}")
        return 1
    if args.analyze:
        analyze_dump_for_patterns(args.dump_file)
        response = input("\nContinue with extraction? (y/n): ")
        if response.lower() != 'y':
            return 0
    extractor = JavaClassExtractor(args.dump_file, args.output)
    extractor.extract_classes()
    if os.path.exists(args.output):
        print("\nVerifying extracted files...")
        verify_class_files(args.output)
    log_file = Path(args.output) / "extraction_log.txt"
    if log_file.exists():
        with open(log_file, 'r') as f:
            lines = f.readlines()
            if len(lines) > 1:
                print(f"\nExtraction Summary:")
                print(f"Total CAFEBABE signatures found: {extractor.cafebabe_count}")
                print(f"Successfully extracted classes: {len(lines) - 1}")
                print(f"Extraction rate: {((len(lines) - 1) / extractor.cafebabe_count * 100):.1f}%")
                print(f"Log file: {log_file}")
                methods = {}
                for line in lines[1:]:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        filename = parts[2]
                        if 'heuristic' in filename:
                            methods['heuristic'] = methods.get('heuristic', 0) + 1
                        elif 'chunk' in filename:
                            methods['chunk'] = methods.get('chunk', 0) + 1
                        else:
                            methods['standard'] = methods.get('standard', 0) + 1
                print("\nExtraction methods:")
                for method, count in methods.items():
                    print(f"  {method}: {count} classes")
    return 0

if __name__ == '__main__':
    exit(main())
