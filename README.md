# Xamarin AssemblyStore Explorer (pyxamstore)
This is an alpha release of an `assemblies.blob` AssemblyStore parser written in Python. The tool is capable of unpack and repackaging `assemblies.blob` and `assemblies.manifest` Xamarin files from an APK.

## Installing
Run the installer script:

    python setup.py install

You can then use the tool by calling `pyxamstore`

## Usage
### Unpacking
I recommend using the tool in conjunction with `apktool`. The following commands can be used to unpack an APK and unpack the Xamarin DLLs:

    apktool d yourapp.apk
    pyxamstore unpack -d yourapp/unknown/assemblies/

Assemblies that are detected as compressed with LZ4 will be automatically decompressed in the extraction process.

### Repacking
If you want to make changes to the DLLs within the AssemblyStore, you can use `pyxamstore` along with the `assemblies.json` generated during the unpack to create a new `assemblies.blob` file(s). The following command from the directory where your `assemblies.json` file exists:

    pyxamstore pack

From here you'll need to copy the new manifest and blobs as well as repackage/sign the APK.

# Additional Details
Additional file format details can be found on my [personal website](https://www.thecobraden.com/posts/unpacking_xamarin_assembly_stores/).

# Known Limitations
* Python3 support (working on it!)
* DLLs that have debug/config data associated with them
