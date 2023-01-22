#
# Copyright © 2022 Samuel Holland <samuel@sholland.org>
# SPDX-License-Identifier: MIT
#

import logging
import sys
import time

from argparse               import ArgumentParser
from binascii               import crc32
from configparser           import ConfigParser
from ctypes                 import *
from enum                   import Enum
from hashlib                import sha256
from pathlib                import Path
from typing                 import Optional, Sequence, Tuple

from elftools.elf.elffile   import ELFFile
from elftools.elf.segments  import Segment
from serial                 import Serial

sys.path.append(str(Path(__file__).with_name('bflb-mcu-tool')))

import bflb_mcu_tool.libs.bl602.bootheader_cfg_keys
import bflb_mcu_tool.libs.bl808.bootheader_cfg_keys

logger = logging.getLogger('loader')

class ErrorName(Enum):
    SUCCESS = 0x00
    ## flash
    FLASH_INIT_ERROR = 0x0001
    FLASH_ERASE_PARA_ERROR = 0x0002
    FLASH_ERASE_ERROR = 0x0003
    FLASH_WRITE_PARA_ERROR = 0x0004
    FLASH_WRITE_ADDR_ERROR = 0x0005
    FLASH_WRITE_ERROR = 0x0006
    FLASH_BOOT_PARA = 0x0007
    ## cmd
    CMD_ID_ERROR  = 0x0101
    CMD_LEN_ERROR = 0x0102
    CMD_CRC_ERROR = 0x0103
    CMD_SEQ_ERROR = 0x0104
    ## image
    IMG_BOOTHEADER_LEN_ERROR = 0x0201
    IMG_BOOTHEADER_NOT_LOAD_ERROR = 0x0202
    IMG_BOOTHEADER_MAGIC_ERROR = 0x0203
    IMG_BOOTHEADER_CRC_ERROR = 0x0204
    IMG_BOOTHEADER_ENCRYPT_NOTFIT = 0x0205
    IMG_BOOTHEADER_SIGN_NOTFIT = 0x0206
    IMG_SEGMENT_CNT_ERROR = 0x0207
    IMG_AES_IV_LEN_ERROR = 0x0208
    IMG_AES_IV_CRC_ERROR = 0x0209
    IMG_PK_LEN_ERROR = 0x020a
    IMG_PK_CRC_ERROR = 0x020b
    IMG_PK_HASH_ERROR = 0x020c
    IMG_SIGNATURE_LEN_ERROR = 0x020d
    IMG_SIGNATURE_CRC_ERROR = 0x020e
    IMG_SECTIONHEADER_LEN_ERROR = 0x020f
    IMG_SECTIONHEADER_CRC_ERROR = 0x0210
    IMG_SECTIONHEADER_DST_ERROR = 0x0211
    IMG_SECTIONDATA_LEN_ERROR = 0x0212
    IMG_SECTIONDATA_DEC_ERROR = 0x0213
    IMG_SECTIONDATA_TLEN_ERROR = 0x0214
    IMG_SECTIONDATA_CRC_ERROR = 0x0215
    IMG_HALFBAKED_ERROR = 0x0216
    IMG_HASH_ERROR = 0x0217
    IMG_SIGN_PARSE_ERROR = 0x0218
    IMG_SIGN_ERROR = 0x0219
    IMG_DEC_ERROR = 0x021a
    IMG_ALL_INVALID_ERROR = 0x021b
    ## IF (internal flash?)
    IF_RATE_LEN_ERROR = 0x0301
    IF_RATE_PARA_ERROR = 0x0302
    IF_PASSWORDERROR = 0x0303
    IF_PASSWORDCLOSE = 0x0304
    ## MISC
    PLL_ERROR = 0xfffc
    INVASION_ERROR = 0xfffd
    POLLING = 0xfffe
    FAIL = 0xffff

    def __str__(self) -> str:
        return self.name

class Chip(Enum):
    BL602 = 'bl602'
    BL808 = 'bl808'

    def __str__(self) -> str:
        return self.value


class Command(Enum):
    GET_CHIP_ID         = 0x05
    GET_BOOT_INFO       = 0x10
    LOAD_BOOT_HEADER    = 0x11
    LOAD_PUBLIC_KEY     = 0x12
    LOAD_PUBLIC_KEY2    = 0x13
    LOAD_SIGNATURE      = 0x14
    LOAD_SIGNATURE2     = 0x15
    LOAD_AES_IV         = 0x16
    LOAD_SEG_HEADER     = 0x17
    LOAD_SEG_DATA       = 0x18
    CHECK_IMAGE         = 0x19
    RUN_IMAGE           = 0x1a
    CHANGE_RATE         = 0x20
    RESET               = 0x21
    FLASH_ERASE         = 0x30
    FLASH_WRITE         = 0x31
    FLASH_READ          = 0x32
    FLASH_BOOT          = 0x33
    EFUSE_WRITE         = 0x40
    EFUSE_READ          = 0x41


def make_boot_header_fields(chip: Chip):
    def keys_to_tuples() -> Sequence[Tuple[int, int, int, str]]:
        '''
        Convert the dictionary to a sortable sequence of offset/size/name tuples.
        '''
        raw_cfg_keys = {
            Chip.BL602: bflb_mcu_tool.libs.bl602.bootheader_cfg_keys.bootheader_cfg_keys,
            Chip.BL808: bflb_mcu_tool.libs.bl808.bootheader_cfg_keys.bootheader_cfg_keys,
        }

        for name, cfg in raw_cfg_keys[chip].items():
            yield int(cfg['offset']), int(cfg['pos']), int(cfg['bitlen']), name

    def pad_name(bit_start: int, byte_start: int) -> str:
        '''
        Generate a name for a padding field.
        '''
        return f'rsvd_{bit_start}_{byte_start}'

    def tuples_to_fields() -> Sequence[Tuple]:
        '''
        Convert the sorted offset/size/name tuples to a ctypes field list.
        '''
        last_byte_end = 0
        last_bit_end = 0
        for byte_start, bit_start, bit_length, name in sorted(keys_to_tuples()):
            if last_byte_end != byte_start:
                logger.debug(f'{chip.name}: {byte_start - last_byte_end:2d} byte gap before {name}')
                if last_bit_end != 0:
                    pad_length = 32 - last_bit_end
                    yield pad_name(last_byte_end, last_bit_end), c_uint32, pad_length
                    last_byte_end += 4
                    last_bit_end = 0
                while last_byte_end < byte_start:
                    yield pad_name(last_byte_end, last_bit_end), c_uint32
                    last_byte_end += 4
                if last_byte_end != byte_start:
                    logger.error(f'{chip}: byte alignment error at {name}!')
            if last_bit_end < bit_start:
                logger.debug(f'{chip.name}: {bit_start - last_bit_end:2d} bit gap before {name}')
                pad_length = bit_start - last_bit_end
                yield pad_name(last_byte_end, last_bit_end), c_uint32, pad_length
                last_bit_end = bit_start
            if last_bit_end != bit_start:
                logger.error(f'{chip.name}: bit alignment error at {name}!')
            if bit_length < 32:
                yield name, c_uint32, bit_length
            else:
                yield name, c_uint32
            last_bit_end += bit_length
            if last_bit_end > 32:
                logger.error(f'{chip.name}: bit count error at {name}!')
            elif last_bit_end == 32:
                last_byte_end += 4
                last_bit_end = 0

    return tuple(tuples_to_fields())


class BootHeader(Structure):
    @classmethod
    def from_config(cls, path: Path, section: str):
        config = ConfigParser()
        config.read(path)
        h = cls()
        for field, value in config.items(section):
            setattr(h, field, int(value, 0))
        return h

    def __repr__(self) -> str:
        values = ', '.join(f'{f}={v:#x}' for f, v in self._asdict().items())
        return f'{self.__class__.__name__}({values})'

    def _asdict(self) -> dict:
        return {field[0]: getattr(self, field[0]) for field in self._fields_}

    def _pretty_print(self) -> str:
        print(self.__class__.__name__ + ':')
        for field, value in self._asdict().items():
            print(f' {field:30s} = {value:#10x}')

    def check_crc32(self) -> bool:
        return self.crc32 == crc32(bytes(self)[:-4])

    def update_crc32(self):
        cls = type(self)

        start = cls.flashcfg_magic_code.offset + 4
        end = cls.flashcfg_crc32.offset
        self.flashcfg_crc32 = crc32(bytes(self)[start:end])

        start = cls.clkcfg_magic_code.offset + 4
        end = cls.clkcfg_crc32.offset
        self.clkcfg_crc32 = crc32(bytes(self)[start:end])

        self.crc32 = crc32(bytes(self)[:-4])

    def update_hash(self, hash: bytes):
        memmove(byref(self, type(self).hash_0.offset), hash, len(hash))


class BL602BootHeader(BootHeader):
    _fields_ = make_boot_header_fields(Chip.BL602)


class BL808BootHeader(BootHeader):
    _fields_ = make_boot_header_fields(Chip.BL808)


class SegmentHeader(Structure):
    _fields_ = (
        ('address', c_uint32),
        ('length',  c_uint32),
        ('rsvd',    c_uint32),
        ('crc32',   c_uint32),
    )

    @classmethod
    def from_elf_segment(cls, elf_segment: Segment):
        h = cls()
        h.address = elf_segment.header.p_paddr
        h.length = elf_segment.header.p_filesz
        h.update_crc32()
        return h

    def check_crc32(self) -> bool:
        return self.crc32 == crc32(bytes(self)[:-4])

    def update_crc32(self) -> bool:
        self.crc32 = crc32(bytes(self)[:-4])


class ISPCommand(Structure):
    _fields_ = (
        ('cmd',     c_uint8),
        ('rsvd',    c_uint8),
        ('length',  c_uint16),
    )

boot_header_classes = {
    Chip.BL602: BL602BootHeader,
    Chip.BL808: BL808BootHeader,
}

boot_header_sections = {
    Chip.BL602: 'BOOTHEADER_CFG',
    Chip.BL808: 'BOOTHEADER_GROUP0_CFG',
}

MAX_CHUNK_SIZE = 4096

AES_IV = '112233445566778899aabbccddeeff00'

FLASH_ADDR = 0x58000000
FLASH_SIZE = 16 * 1024 * 1024
BOOTROM_ADDR = 0x90000000
BOOTROM_SIZE = 128 * 1024

FOUR_K = (4096).to_bytes(4, 'little')


def load_elf_file(chip: Chip, cfg_path: Optional[Path], elf_path: Path, elf_path2: Path, serial_port: Path, baud: int):
    boot_header_class = boot_header_classes[chip]
    if cfg_path:
        cfg_section = boot_header_sections[chip]
        boot_header = boot_header_class.from_config(cfg_path, cfg_section)
    else:
        boot_header = boot_header_class()

    segments = []
    # Extract the segments from the ELF file.
    with ELFFile(elf_path.open('rb')) as elf_file:
        for elf_segment in elf_file.iter_segments():
            # Skip non-loadable segments.
            if elf_segment.header.p_filesz == 0 or \
               elf_segment.header.p_type != 'PT_LOAD':
                continue

            logger.info(f'ELF1 segment ({elf_segment.header.p_type}) @ {elf_segment.header.p_paddr:08x}')
            segments.append((
                SegmentHeader.from_elf_segment(elf_segment),
                elf_segment.data(),
            ))

    if elf_path2 is not None:
        with ELFFile(elf_path2.open('rb')) as elf_file2:
            for elf_segment in elf_file2.iter_segments():
                # Skip non-loadable segments.
                if elf_segment.header.p_filesz == 0 or \
                   elf_segment.header.p_type != 'PT_LOAD':
                    continue
                logger.info(f'ELF2 segment ({elf_segment.header.p_type}) @ {elf_segment.header.p_paddr:08x}')
                segments.append((
                    SegmentHeader.from_elf_segment(elf_segment),
                    elf_segment.data(),
                ))

    # Generate the SHA-256 hash for the entire loaded image.
    image_hash = sha256()
    for segment_header, data in segments:
        image_hash.update(segment_header)
        image_hash.update(data)

    # Update the boot header from the ELF file.
    if chip == Chip.BL808:
        boot_header.img_len_cnt = len(segments)
        logger.info(f'Entry point {elf_file.header.e_entry:08x}')
        boot_header.m0_boot_entry = elf_file.header.e_entry
    else:
        boot_header.img_len = len(segments)
        boot_header.img_start = elf_file.header.e_entry
    boot_header.update_hash(image_hash.digest())
    boot_header.update_crc32()

    # boot_header._pretty_print()

    with Serial(str(serial_port), baud) as serial:
        def dump_mem(start: int, length: int, file_name: str):
            chunks = length // 4096
            with open(file_name, "wb") as dump:
                for offset in range(0, chunks):
                    addr = start + offset*4096
                    args = b''.join([addr.to_bytes(4, 'little'), FOUR_K])
                    logger.info(f'{addr:#x} ({offset}) - {args}')
                    send_command(Command.FLASH_READ, args)
                    res = serial.read(4096)
                    dump.write(res)

        def send_command(cmd: Command, data: bytes):
            serial.write(ISPCommand(cmd=cmd.value, length=len(data)))
            serial.write(data)
            status = serial.read(2)
            # logger.info(f'send command {cmd:#x}')
            if status != b'OK':
                err = int.from_bytes(serial.read(2), 'little')
                errname = ErrorName(err)
                raise Exception(f'Command {cmd:#x} failed: {err:#06x} ({errname})')
            # Some commands produce a response that must be handled.
            if cmd == Command.GET_BOOT_INFO:
                length = int.from_bytes(serial.read(2), 'little')
                response = serial.read(length)
                logger.info(f'Boot info: {response.hex()}')
            if cmd == Command.LOAD_SEG_HEADER:
                length = int.from_bytes(serial.read(2), 'little')
                if length != len(data):
                    raise Exception('Unexpected response length')
                logger.info(f'bl808 sends {length} bytes')
                # Discard the response? Unless the firmware is encrypted,
                # it will be identical to the segment header we just sent.
                res = serial.read(length)
                logger.info(f'bl808 says {res}')
                # per doc: 4 bytes boot ROM version + 16 bytes OTP info
                # unclear: where are the 2 bits for signature + encryption?
                # I get the following:
                # TODO: boot ROM version; chip version 1 + ID 0808 for BL808?
                # 01000808 (hex)
                # TODO: OTP info, is that settings of fuses?
                # 00000101 0b14c102  e669de05 b9185800  2ff4fb18 (hex)
                # again in binary:
                # 00000000 00000000  00000001 00000001
                # 00001011 00010100  11000001 00000010
                # 11100110 01101001  11011110 00000101
                # 10111001 00011000  01011000 00000000
                # 00101111 11110100  11111011 00011000

                # 01000808
                # 00000101 0b14c102  ea69de05 b9185800  2ff4fb18
            if cmd == Command.FLASH_READ:
                length = int.from_bytes(serial.read(2), 'little')
                logger.info(f'bl808 flash read, sends {length} bytes')
            if cmd == Command.RUN_IMAGE:
                while True:
                    c = serial.read(1)
                    print(c)

        logger.info('Sending handshake...')
        serial.timeout = 0.1
        while True:
            serial.write(b'U' * 32)
            if chip == Chip.BL808:
                logger.info('bl808 magic')
                serial.write(bytes.fromhex('5000080038F0002000000018'))
            # this sometimes gets 0x6afa
            ## err = int.from_bytes(res, 'little')
            ## errname = ErrorName(err)
            res = serial.read(2)
            if res == b'\x6a\xfa':
                raise Exception(f'Handshake failed with weird error {res}')
            if res == b'OK':
                break
        serial.timeout = None

        # flash read
        # dump_mem(FLASH_ADDR, FLASH_SIZE, "flash.bin")
        # dump_mem(BOOTROM_ADDR, BOOTROM_SIZE, "bootrom.bin")

        logger.info('Getting boot info...')
        send_command(Command.GET_BOOT_INFO, b'')

        logger.info('Sending boot header...')
        send_command(Command.LOAD_BOOT_HEADER, bytes(boot_header))

        # iv = bytes.fromhex(AES_IV)
        # crc = crc32(iv).to_bytes(4, 'little')
        # args = b''.join([iv, crc])
        # logger.info(f'Sending AES IV {iv} ({crc}) - {args}')
        # send_command(Command.LOAD_AES_IV, args)

        for segment_header, data in segments:
            logger.info(f'Sending segment {segment_header.address:08x}+{segment_header.length:08x} ({segment_header.crc32:08x})')
            send_command(Command.LOAD_SEG_HEADER, bytes(segment_header))
            while data:
                chunk, data = data[:MAX_CHUNK_SIZE], data[MAX_CHUNK_SIZE:]
                send_command(Command.LOAD_SEG_DATA, chunk)

        logger.info('Checking image...')
        send_command(Command.CHECK_IMAGE, b'')

        logger.info('Running image...')
        send_command(Command.RUN_IMAGE, b'')


def main():
    parser = ArgumentParser(prog='loader',
                            description="Load an ELF to the MCU's RAM and execute it.")
    parser.add_argument('-b', '--baud',
                        help='Serial port baud rate',
                        default=115200, type=int)
    parser.add_argument('-C', '--cfg',
                        help='Config file with values for boot header fields',
                        type=Path)
    parser.add_argument('-c', '--chip',
                        help='MCU variant connected to the serial port',
                        default=Chip.BL808, type=Chip, choices=tuple(Chip))
    parser.add_argument('-p', '--port',
                        help='Serial port device path',
                        default=Path('/dev/ttyS0'), type=Path)
    parser.add_argument('firmware',
                        help='ELF executable file path for C906 core',
                        type=Path)
    parser.add_argument('firmware2',
                        help='ELF executable file path for E907 core',
                        type=Path)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    try:
        load_elf_file(args.chip, args.cfg, args.firmware, args.firmware2, args.port, args.baud)
    except Exception as e:
        logger.exception('Failed to communicate with the MCU')

if __name__ == '__main__':
    main()
