import hashlib
import pefile
import sys
import hashlib
import time

print("\ngetHashes.py - a tool to gather PE related hashes, for malware analysis")
print("Usage: getHashes.py <file>\n")

def get_hashes():

    BUF_SIZE = 32768
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        file = sys.argv[1]
        pe = pefile.PE(file)
    except:
        print("[!] Failed to load provided file")
        sys.exit(1)
        
    print("Filename: {}".format(file))
    
    timestamp = pe.FILE_HEADER.TimeDateStamp
    print("Compile timestamp: " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)))
    
    print("\nFile hashes:")
    print("\tImphash {} ".format(pe.get_imphash()).upper())
    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)

    print("\tMD5\t{}".format(md5.hexdigest()).upper())
    print("\tSHA1\t{}".format(sha1.hexdigest()).upper())
    print("\tSHA256\t{}".format(sha256.hexdigest()).upper())

    print("\nPE Sections (MD5):")
    for sect in pe.sections:
        print("\t" + sect.Name.decode('utf-8') + sect.get_hash_md5().upper())

if __name__ == "__main__":
    get_hashes()
