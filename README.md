# Unpacking Xamarin assemblies.blob Files
This is an alpha release of an `assemblies.blob` AssemblyStore parser written in Python. The tool expects an `assemblies.blob` and `assemblies.manifest` from an APK. Not all files may be supported at this time.

## Usage
To use, simply unpack the required files and run the tool:

    unzip base.apk assemblies/assemblies.blob assemblies/assemblies.manifest
    python unpack-store.py -b assemblies.blob -m assemblies.manifest

Assemblies that are detected as compressed with LZ4 will be automatically decompressed in the extraction process.

Additional file format details can be found on my [personal website](https://www.thecobraden.com/posts/unpacking_xamarin_assembly_stores/).
