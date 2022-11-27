#!/usr/bin/python2

import struct
import argparse
import os
import os.path
import lz4.block

ASSEMBLY_STORE_MAGIC = b"XABA"
ASSEMBLY_STORE_FORMAT_VERSION = 1

COMPRESSED_ASSEMBLY_MAGIC = b"XALZ"


class ManifestEntry(object):

    """Element in Manifest"""

    hash32 = ""
    hash64 = ""
    blob_idx = 0
    name = ""

    def __init__(self, hash32, hash64, blob_idx, name):

        """Initialize item"""

        self.hash32 = hash32
        self.hash64 = hash64
        self.blob_idx = int(blob_idx)
        self.name = name


class ManifestList(list):

    """List of manifest entries"""

    def get_idx(self, idx):

        """Find entry by ID"""

        for entry in self:
            if entry.blob_idx == idx:
                return entry
        return None


class AssemblyStoreAssembly(object):

    """Assembly Details"""

    data_offset = 0
    data_size = 0
    debug_data_offset = 0
    debug_data_size = 0
    config_data_offset = 0
    config_data_size = 0

    def __init__(self):
        pass


class AssemblyStoreHashEntry(object):

    """Hash Details"""

    hash_val = ""
    mapping_index = 0
    local_store_index = 0
    store_id = 0

    def __init__(self):
        pass


class AssemblyStore(object):

    """AssemblyStore object"""

    raw = ""

    manifest_entries = None

    hdr_magic = ""
    hdr_version = 0
    hdr_lec = 0
    hdr_gec = 0
    hdr_store_id = 0

    assembly_list = None
    global_hash32 = None
    global_hash64 = None

    def __init__(self, in_file_name, manifest_entries):

        """Parse and read store"""

        self.manifest_entries = manifest_entries

        blob_file = open(in_file_name, "rb")

        self.raw = blob_file.read()

        blob_file.seek(0)

        # Header Section
        #
        # 0  -  3: Magic
        # 4  -  7: Version
        # 8  - 11: LocalEntryCount
        # 12 - 15: GlobalEntryCount
        # 16 - 19: StoreID

        magic = blob_file.read(4)
        if magic != ASSEMBLY_STORE_MAGIC:
            raise Exception("Invalid Magic: %s" % magic)

        version = struct.unpack("I", blob_file.read(4))[0]
        if version > ASSEMBLY_STORE_FORMAT_VERSION:
            raise Exception("This version is higher than expected! Max = %d, got %d"
                            % ASSEMBLY_STORE_FORMAT_VERSION, version)

        self.hdr_version = version

        self.hdr_lec = struct.unpack("I", blob_file.read(4))[0]
        self.hdr_gec = struct.unpack("I", blob_file.read(4))[0]
        self.hdr_store_id = struct.unpack("I", blob_file.read(4))[0]

        print("Number of local entries to extract: %d" % self.hdr_lec)

        self.assemblies_list = list()

        i = 0
        while i < self.hdr_lec:

            #  0 -  3: DataOffset
            #  4 -  7: DataSize
            #  8 - 11: DebugDataOffset
            # 12 - 15: DebugDataSize
            # 16 - 19: ConfigDataOffset
            # 20 - 23: ConfigDataSize

            entry = blob_file.read(24)

            assembly = AssemblyStoreAssembly()

            assembly.data_offset = struct.unpack("I", entry[0:4])[0]
            assembly.data_size = struct.unpack("I", entry[4:8])[0]
            assembly.debug_data_offset = struct.unpack("I", entry[8:12])[0]
            assembly.debug_data_size = struct.unpack("I", entry[12:16])[0]
            assembly.config_data_offset = struct.unpack("I", entry[16:20])[0]
            assembly.config_data_size = struct.unpack("I", entry[20:24])[0]

            self.assemblies_list.append(assembly)

            i += 1

        # Parse Hash data
        self.global_hash32 = list()

        i = 0
        while i < self.hdr_lec:

            entry = blob_file.read(20)

            hash_entry = AssemblyStoreHashEntry()

            hash_entry.hash_val = "0x%08x" % struct.unpack("<I", entry[0:4])[0]
            hash_entry.mapping_index = struct.unpack("I", entry[8:12])[0]
            hash_entry.local_store_index = struct.unpack("I", entry[12:16])[0]
            hash_entry.store_id = struct.unpack("I", entry[16:20])[0]

            self.global_hash32.append(hash_entry)

            i += 1

        self.global_hash64 = list()

        i = 0
        while i < self.hdr_lec:

            entry = blob_file.read(20)

            hash_entry = AssemblyStoreHashEntry()

            hash_entry.hash_val = "0x%016x" % struct.unpack("<Q", entry[0:8])[0]
            hash_entry.mapping_index = struct.unpack("I", entry[8:12])[0]
            hash_entry.local_store_index = struct.unpack("I", entry[12:16])[0]
            hash_entry.store_id = struct.unpack("I", entry[16:20])[0]

            self.global_hash64.append(hash_entry)

            i += 1

    def extract_all(self, outpath="out"):

        """Extract everything"""

        if os.path.isdir(outpath):
            print("Out directory already exists!")
            return 4

        os.mkdir(outpath)

        i = 0
        for assembly in self.assemblies_list:

            assembly_data = ""

            entry = self.manifest_entries.get_idx(i)

            # Check if compressed, otherwise write
            assembly_header = self.raw[assembly.data_offset:assembly.data_offset+4]
            if assembly_header == COMPRESSED_ASSEMBLY_MAGIC:
                assembly_data = self.decompress_lz4(self.raw[assembly.data_offset:
                                                    assembly.data_offset
                                                    + assembly.data_size])
            else:
                assembly_data = self.raw[assembly.data_offset:
                                         assembly.data_offset + assembly.data_size]

            print("Extracting %s..." % entry.name)
            wfile = open("%s/%s.dll" % (outpath, entry.name), "wb")

            wfile.write(assembly_data)
            wfile.close()
            i += 1

    @classmethod
    def decompress_lz4(cls, compressed_data):

        """Unpack an assembly if LZ4 packed"""

        # From: https://github.com/securitygrind/lz4_decompress
        packed_payload_len = compressed_data[8:12]
        unpacked_payload_len = struct.unpack('<I', packed_payload_len)[0]
        compressed_payload = compressed_data[12:]

        return lz4.block.decompress(compressed_payload,
                                    uncompressed_size=unpacked_payload_len)


def read_manifest(in_manifest):

    """Read Manifest entries"""

    manifest_list = ManifestList()
    for line in open(in_manifest, "rb").read().split(b"\n"):
        if line == "" or len(line) == 0:
            continue
        if line[0:4] == "Hash":
            continue

        split_line = line.split()

        manifest_list.append(ManifestEntry(split_line[0].decode(),   # hash32
                                           split_line[1].decode(),   # hash64
                                           split_line[3],            # blob_idx
                                           split_line[4].decode()))  # name

    return manifest_list


def process_blob(in_blob, in_manifest, check_hash=False):

    manifest_entries = read_manifest(in_manifest)

    if manifest_entries is None:
        print("Unable to parse assemblies.manifest file!")
        return 3

    assembly_store = AssemblyStore(in_blob, manifest_entries)

    return assembly_store.extract_all()


def main():

    parser = argparse.ArgumentParser(description='Parse DLLs from assemblies.blob store.')
    parser.add_argument('--blob', '-b', type=str,
                        help='Input assemblies.blob file.')
    parser.add_argument('--manifest', '-m', type=str,
                        help='Input assemblies.manifest file.')

    args = parser.parse_args()

    if args.blob is None or args.manifest is None:
        print("Need blob + manifest!")
        return 1

    return process_blob(args.blob, args.manifest)


if __name__ == "__main__":
    main()
