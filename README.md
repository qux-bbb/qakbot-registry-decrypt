# Qakbot Registry Key Configuration Decryptor

This is a decryptor for Qakbot's configuration stored in the registry key

## Python 3 requirements

```r
arc4==0.0.4
bitstring==3.1.9
hexdump==3.3
pycryptodome==3.12.0
pywin32==303
```

## Usage
```
Usage: qakbot-registry-decrypt.py [options]

Options:
  -h, --help            show this help message and exit
  -r REGISTRY_PATH, --regpath=REGISTRY_PATH
                        registry path where Qakbot's encrypted data is stored.
                        (e.g. 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Efwramsn')
                        (optional)
  -p PASSWORD, --password=PASSWORD
                        password (optional)
```

### Test Sample
MD5:  
90aac91ba4336bdb252dee699d32d78d  
c9d028d84f4ac475afde0f938f536262  

https://www.virustotal.com/gui/file/edfe1d500855331f71ef12b7e459af1224a5ff3bca89ab7cd0dac930fd77c41a/detection  
https://www.virustotal.com/gui/file/7f6b834ac2abebb93daeefb7fbc2e8d41280c8a28e2cc00e47816f3ef5ffa756/detection  
