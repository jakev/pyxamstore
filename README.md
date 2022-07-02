# Unpacking Xamarin assemblies.blob Files
This is an alpha release of an `assemblies.blob` AssemblyStore parser written in Python (unfortunately Py2 for now). The tool expects an `assemblies.blob` and `assemblies.manifest` from an APK. Not all files may be supported at this time.

## Usage
To use, simply unpack the required files and run the tool:

    unzip base.apk assemblies/assemblies.blob assemblies/assemblies.manifest
    python unpack-store.py -b assemblies.blob -m assemblies.manifest

This will create a number of files in the `out/` directory ending in `.lz4` (at this point the tool assumes LZ4 packed DLLs). Since these are also not readable, you'll need to unpack these `.lz4` files using a tool such as [lz4\_decompress.py](https://github.com/securitygrind/lz4_decompress/blob/main/lz4_decompress.py):

    python lz4_decompress.py out/TestApp.lz4
