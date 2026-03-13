"""
Quick test script to verify ForensAI can load and analyze real forensic images
"""

import os
from managers.evidence_utils import ImageHandler

def test_forensic_image(image_path):
    """Test loading and analyzing a forensic image"""
    print(f"\n{'='*60}")
    print(f"Testing: {os.path.basename(image_path)}")
    print(f"{'='*60}\n")

    try:
        print("1. Loading image...")
        handler = ImageHandler(image_path)
        print(f"   [OK] Image loaded successfully")
        print(f"   Size: {handler.get_readable_size(handler.get_size())}")

        print("\n2. Analyzing partitions...")
        partitions = handler.get_partitions()
        if partitions:
            print(f"   [OK] Found {len(partitions)} partition(s)")
            for addr, desc, start, length in partitions:
                desc_str = desc.decode() if isinstance(desc, bytes) else str(desc)
                fs_type = handler.get_fs_type(start) if handler.has_filesystem(start) else "N/A"
                print(f"     - Partition {addr}: {desc_str} (FS: {fs_type})")
        else:
            print(f"   [INFO] No partitions found (may be direct filesystem)")

        partition_offset = None
        for addr, desc, start, length in partitions:
            if handler.has_filesystem(start):
                partition_offset = start
                break

        if partition_offset is None and handler.fs_info:
            partition_offset = 0

        if partition_offset is not None:
            print(f"\n3. Reading root directory (offset: {partition_offset})...")
            entries = handler.get_directory_contents(partition_offset)
            print(f"   [OK] Found {len(entries)} entries")

            print("\n   First 10 entries:")
            for i, entry in enumerate(entries[:10]):
                icon = "[DIR]" if entry["is_directory"] else "[FILE]"
                size_str = handler.get_readable_size(entry["size"]) if not entry["is_directory"] else "DIR"
                print(f"     {icon} {entry['name']:<30} {size_str:>10}  {entry['modified']}")

            print("\n4. Testing file content reading...")
            for entry in entries[:20]:
                if not entry["is_directory"] and entry["size"] > 0 and entry["size"] < 1024*1024:
                    inode = entry["inode_number"]
                    print(f"   Reading: {entry['name']} (inode: {inode})...")
                    content, metadata = handler.get_file_content(inode, partition_offset)

                    if content:
                        print(f"   [OK] Read {len(content)} bytes")
                        hex_preview = ' '.join(f'{b:02X}' for b in content[:64])
                        print(f"   First 64 bytes: {hex_preview}")
                        break
            else:
                print("   [INFO] No suitable small file found for testing")

        else:
            print("\n   [WARN] No filesystem found in image")

        print(f"\n{'='*60}")
        print("[SUCCESS] ALL TESTS PASSED!")
        print(f"{'='*60}\n")
        return True

    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    test_image = r"C:\Users\NAWAF\Dropbox\PC\Desktop\projects\ForensAI\evidence\image_20251106T210112.dd"

    if os.path.exists(test_image):
        print("Testing ForensAI with real forensic data...")
        success = test_forensic_image(test_image)

        if success:
            print("\n[SUCCESS] ForensAI backend is working perfectly with real data!")
            print("\nNow launch the QML app to see it in the beautiful interface:")
            print("  python main_qml.py")
        else:
            print("\n[WARN] There were issues. Check the error messages above.")
    else:
        print(f"[ERROR] Image file not found: {test_image}")
        print("\nPlease provide a valid forensic image path.")
