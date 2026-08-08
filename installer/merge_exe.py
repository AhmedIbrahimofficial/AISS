"""
Merges AISS_Setup.exe + AISS_v2.0_Windows_Portable.zip
into one single AISS_Full_Setup.exe

The installer reads the ZIP from its own exe file at runtime.
"""
import struct, shutil
from pathlib import Path

OUT   = Path(__file__).parent / "output"
SETUP = OUT / "AISS_Setup.exe"
ZIP   = OUT / "AISS_v2.0_Windows_Portable.zip"
FINAL = OUT / "AISS_Full_Setup.exe"

MAGIC = b"AISS_ZIP_START_MARKER_8675309"

def merge():
    print(f"Setup.exe : {SETUP.stat().st_size / 1024 / 1024:.1f} MB")
    print(f"ZIP       : {ZIP.stat().st_size   / 1024 / 1024:.1f} MB")
    print(f"\nMerging into single EXE...")

    zip_data   = ZIP.read_bytes()
    setup_data = SETUP.read_bytes()

    # Format: [setup_exe][MAGIC][zip_size_8bytes][zip_data]
    zip_size = struct.pack("<Q", len(zip_data))

    with open(FINAL, "wb") as f:
        f.write(setup_data)
        f.write(MAGIC)
        f.write(zip_size)
        f.write(zip_data)

    size_mb = FINAL.stat().st_size / 1024 / 1024
    print(f"\n✅ AISS_Full_Setup.exe created: {size_mb:.1f} MB")
    print(f"   {FINAL}")
    print(f"\nSend ONLY this one file to your friend.")
    print(f"They double-click it → License → Choose path → Installs everything → Done.")

if __name__ == "__main__":
    merge()
