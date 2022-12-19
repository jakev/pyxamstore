"""Global Values"""


# AssemblyStore Constants
ASSEMBLY_STORE_MAGIC = b"XABA"
ASSEMBLY_STORE_FORMAT_VERSION = 1

COMPRESSED_DATA_MAGIC = b"XALZ"

# Assemblies related
FILE_ASSEMBLIES_BLOB = "assemblies.blob"
FILE_ASSEMBLIES_BLOB_ARM = "assemblies.armeabi_v7a.blob"
FILE_ASSEMBLIES_BLOB_ARM_64 = "assemblies.arm64_v8a.blob"
FILE_ASSEMBLIES_BLOB_x86 = "assemblies.x86.blob"
FILE_ASSEMBLIES_BLOB_x86_64 = "assemblies.x86_64.blob"

ARCHITECTURE_MAP = {"arm": FILE_ASSEMBLIES_BLOB_ARM,
                    "arm64": FILE_ASSEMBLIES_BLOB_ARM_64,
                    "x86": FILE_ASSEMBLIES_BLOB_x86,
                    "x86_64": FILE_ASSEMBLIES_BLOB_x86_64}

FILE_ASSEMBLIES_MANIFEST = "assemblies.manifest"

# Output / Internal
FILE_ASSEMBLIES_JSON = "assemblies.json"
