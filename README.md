# Xamarin AssemblyStore Explorer (pyxamstore)
This is an alpha release of an `assemblies.blob` AssemblyStore parser written in Python. The tool is capable of unpack and repackaging `assemblies.blob` and `assemblies.manifest` Xamarin files from an APK.

## Installing
Run the installer script:

    python setup.py install

You can then use the tool by calling `pyxamstore`

## Usage
### Unpacking
To use, simply unpack the required files and run the tool:

    unzip base.apk assemblies/assemblies.blob assemblies/assemblies.manifest
    cd assemblies/
    pyxamstore unpack

Assemblies that are detected as compressed with LZ4 will be automatically decompressed in the extraction process.

### Repacking
If you want to make changes to the DLLs within the AssemblyStore, you can use `pyxamstore` along with the `assemblies.json` generated during the unpack to create a new `assemblies.blob` file. The following command from the directory where your `assemblies.json` file exists:

    pyxamstore pack

From here you'll need to repackage/sign the APK.

# Additional Details
Additional file format details can be found on my [personal website](https://www.thecobraden.com/posts/unpacking_xamarin_assembly_stores/).
