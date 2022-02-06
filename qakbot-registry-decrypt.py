# coding:utf8

import re
import sys
import hexdump
import winreg
import win32api
import binascii

from optparse import OptionParser
from Crypto.Cipher import ARC4
from hashlib import sha1
from struct import pack


tbl4 = [ 0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c]

def mit_crc32_shift4(data, seed):
    crc = ~seed & 0xffffffff
    for byte in data:
        x = tbl4[(byte ^ crc ) & 0x0f] ^ (((byte ^ crc) & 0xffffffff)  >> 4)
        crc = tbl4[x & 0x0f] ^  ((x & 0xffffffff) >> 4)
    return ~crc & 0xffffffff

def widen_string(string):
    s = string.encode('utf-16')
    return s[2:] if s[:2] == b'\xff\xfe' else s

def precalculate_reg_names(key):
    """precalculate registry names, returns a dictionary {'regname':'id'} """
    reg_names = {}
    for i in range(0,0xff):
        reg_names[hex(mit_crc32_shift4(pack('I',i), key))[2:]] = i
    return reg_names

def get_all_reg_values(reg_key):
    """gets all qakbot registry value"""
    regs = {}
    i = 0
    while True:
        try:
            vname, value, vtype = winreg.EnumValue(reg_key, i)
            regs[vname] = value
        except WindowsError as e:
            break
        i+=1
    return regs

def get_password():
    """gets the computer name, C: drive volume serial number, and account name"""

    computer_name = win32api.GetComputerName()
    volume_serial_number = win32api.GetVolumeInformation('C:\\')[1] & 0xffffffff
    user_account_name = win32api.GetUserName()

    return widen_string(('{}{}{}'.format(computer_name,volume_serial_number,user_account_name)).upper())


class MT19937:
    def __init__(self, seed):
        self.mt = [0] * 624
        self.mt[0] = seed
        self.mti = 0
        for i in range(1, 624):
            self.mt[i] = MT19937._int32(1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def _int32(x):
        return int(0xFFFFFFFF & x)

    def extract_number(self):
        if self.mti == 0:
            self.twist()
        y = self.mt[self.mti]
        y = y ^ y >> 11
        y = y ^ y << 7 & 2636928640
        y = y ^ y << 15 & 4022730752
        y = y ^ y >> 18
        self.mti = (self.mti + 1) % 624
        return MT19937._int32(y)

    def twist(self):
        for i in range(0, 624):
            y = MT19937._int32((self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = (y >> 1) ^ self.mt[(i + 397) % 624]

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df

def get_limited_random_num(a_MT19937, a, b):
    v3 = a_MT19937.extract_number() & 0xFFFFFFF
    return a - int((b - a + 1) * (v3 * -0.000000003725290298461914))


def main():
    parser = OptionParser()
    parser.add_option('-r','--regpath', 
        type='string', 
        dest='registry_path',
        help="registry path where Qakbot's encrypted data is stored. (e.g. 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Efwramsn') (optional)")
    parser.add_option('-p', '--password', 
        type='string', 
        dest='password',
        help="password (optional)")
    (options, args) = parser.parse_args()

    if options.password:
        password = options.password
    else:
        password = get_password()
        if not password:
            print('Error collecting password string')
            sys.exit(0)

    the_registry_path = ''
    if options.registry_path:
        root_match = re.match(r'^([Hh][a-zA-Z_]*?)\\(.*?)$',options.registry_path)
        if root_match:
            root = root_match.group(1)
            try:
                if root.upper() == 'HKLM' or root.upper() == 'HKEY_LOCAL_MACHINE':
                    regkey = winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, root_match.group(2))
                if root.upper() == 'HKCU' or root.upper() == 'HKEY_CURRENT_USER':
                    regkey = winreg.OpenKeyEx(winreg.HKEY_CURRENT_USER, root_match.group(2))
                the_registry_path = options.registry_path
            except WindowsError as e:
                print('Failed to open registry key')
                sys.exit(0)
        else:
            print('Registry key path format not allowed.')
            sys.exit(0)
    else:
        seed = binascii.crc32(password)
        the_MT19937 = MT19937(seed)
        the_len = get_limited_random_num(the_MT19937, 7, 14)

        basic_str = "aabcdeefghiijklmnoopqrstuuvwxyyz"
        basic_str_len = len(basic_str)
        random_key = ''
        for i in range(the_len):
            if i > 32:
                break
            tmp_index = get_limited_random_num(the_MT19937, 0, basic_str_len-1)
            random_key += basic_str[tmp_index]
        random_key = random_key.capitalize()

        subkey = 'Software\\Microsoft\\' + random_key
        the_registry_path = 'HKEY_CURRENT_USER' + '\\' + subkey
        try:
            regkey = winreg.OpenKeyEx(winreg.HKEY_CURRENT_USER, subkey)
        except WindowsError as e:
            print(f'Failed to open registry key: {the_registry_path}')
            sys.exit(0)

    print('Using password (in UTF-16): "{}"'.format(password.decode('utf-16')))
    password_hash = mit_crc32_shift4(password,0)            # calculate password's crc32_shift4 hash 
    print('Password CRC32_shift4 Hash: {}\n'.format(hex(password_hash)))
    
    precalc_regs = precalculate_reg_names(password_hash)    # precalculate registry names for lookup
    all_regs = get_all_reg_values(regkey)                   # collect all registry name/values from Qakbot's registry path

    if not all_regs.__len__():
        print('Registry path is empty')
        sys.exit(0)

    for name,value in all_regs.items():
        id_salt = precalc_regs[name]                          # lookup registry names from precalculated table (dictionary)
        key = pack('I',id_salt) + pack('I',password_hash)     # prepend salt to password hash
        derived_key = sha1(key).digest()                      # hash salted key with SHA1 
        cipher = ARC4.new(derived_key)                        # use SHA1 hash as RC4 key
        msg = cipher.decrypt(value)                           # decrypt registry value data 
        print("Registry key path: {}\nRC4 key: {}\nDecrypted value:\n{}\n".format(
            the_registry_path+"\\"+name,
            ' '.join(format(x, '02x') for x in derived_key),
            hexdump.hexdump(msg, result="return")))


if __name__ == '__main__':
    main()
