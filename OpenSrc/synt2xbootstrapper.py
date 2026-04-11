global discord_rpc
global status_window
global launcher_mutex
import os
import sys
import time
import json
import hashlib
import shutil
import zipfile
import subprocess
import requests
import psutil
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import unquote
import hmac
import struct
import ctypes
from ctypes import wintypes
SECRET_KEY = 'c4f8a2e9d7b3f6e1a8c5d2f9b6e3a7d4c1f8e5b2a9d6f3e0c7b4a1f8e5d2b9c6a3f0e7d4c1b8f5a2e9d6c3b0a7f4e1d8c5b2f9e6a3d0c7f4b1e8d5c2a9f6e3b0d7c4a1f8e5b2d9c6a3f0e7d4b1c8f5a2e9d6b3c0a7f4e1d8c5a2f9e6b3d0c7a4f1e8d5b2c9f6e3a0d7c4b1f8e5a2d9c6b3f0e7d4a1c8f5b2e9d6a3c0b7f4e1d8c5a2f9e6b3d0c7a4f1e8d5b2c9f6e3a0d7c4'
PROCESS_VM_READ = 16
PROCESS_QUERY_INFORMATION = 1024
MEM_COMMIT = 4096
PAGE_EXECUTE_READWRITE = 64
PAGE_EXECUTE_READ = 32
PAGE_EXECUTE_WRITECOPY = 128
SUSPICIOUS_PATTERNS = ['L\x8b\xdcI\x89[\x08','H\x89\\$\x08H\x89t$\x10WH\x83\xec ','U\x8b\xec\x83\xec','\xeb\xfe','L\x8b\x05']
BLACKLISTED_PROCESSES = ['cheatengine','x64dbg','x32dbg','ida','ida64','ollydbg','processhacker','wireshark','fiddler','charles','dnspy','ilspy','reshade','injector','extremeinjector','xenos','processexplorer']
def scan_for_injection_patterns(process_handle,pid):
  '''Scan ONLY private/unmapped memory for injection patterns'''
  suspicious = []
  try:
    kernel32 = ctypes.windll.kernel32
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
      _fields_ = [('BaseAddress',wintypes.LPVOID),('AllocationBase',wintypes.LPVOID),('AllocationProtect',wintypes.DWORD),('RegionSize',ctypes.c_size_t),('State',wintypes.DWORD),('Protect',wintypes.DWORD),('Type',wintypes.DWORD)]

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    while address < 0x7FFFFFFF0000:
      result = kernel32.VirtualQueryEx(process_handle,ctypes.c_void_p(address),ctypes.byref(mbi),ctypes.sizeof(mbi))
      if result == 0:
        pass
        return suspicious
      else:
        if mbi.State == MEM_COMMIT and mbi.Type == 131072 and mbi.Protect&PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE:
          buffer = ctypes.create_string_buffer(min(mbi.RegionSize,4096))
          bytes_read = ctypes.c_size_t()
          if kernel32.ReadProcessMemory(process_handle,ctypes.c_void_p(mbi.BaseAddress),buffer,len(buffer),ctypes.byref(bytes_read)):
            for pattern in SUSPICIOUS_PATTERNS:
              if pattern in buffer.raw:
                suspicious.append({'address':hex(mbi.BaseAddress),'size':mbi.RegionSize,'type':'injection_pattern','pattern':pattern.hex()[:16]})
                break

        address += mbi.RegionSize
        continue
        return suspicious
        return []

  except:
    pass

def scan_memory_regions(process_handle,pid):
  suspicious_regions = []
  try:
    if sys.platform != 'win32':
      return []
    else:
      kernel32 = ctypes.windll.kernel32
      class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [('BaseAddress',wintypes.LPVOID),('AllocationBase',wintypes.LPVOID),('AllocationProtect',wintypes.DWORD),('RegionSize',ctypes.c_size_t),('State',wintypes.DWORD),('Protect',wintypes.DWORD),('Type',wintypes.DWORD)]

      mbi = MEMORY_BASIC_INFORMATION()
      address = 0
      legitimate_ranges = set()
      legitimate_alloc_bases = set()
      try:
        client_process = psutil.Process(pid)
        for module in client_process.memory_maps():
          if is_module_trusted(module.path,Path(module.path).name.lower()):
            addr_range = module.addr.split('-')
            start = int(addr_range[0],16)
            end = int(addr_range[1],16)
            legitimate_ranges.add((start,end))
            legitimate_alloc_bases.add(start)

      except:
        pass

      while address < 0x7FFFFFFF0000:
        result = kernel32.VirtualQueryEx(process_handle,ctypes.c_void_p(address),ctypes.byref(mbi),ctypes.sizeof(mbi))
        if result == 0:
          pass
          return suspicious_regions
        else:
          if mbi.State == MEM_COMMIT:
            base_addr = mbi.BaseAddress
            alloc_base = mbi.AllocationBase
            is_legitimate = False
            for start,end in legitimate_ranges:
              if start <= base_addr and __CHAOS_PY_NULL_PTR_VALUE_ERR__ < end:
                continue

  except:
    (is_legitimate or legitimate_alloc_bases)

def check_process_blacklist():
  '''
Enhanced blacklist check with full process details to avoid false positives
'''
  blacklisted = []
  try:
    for proc in psutil.process_iter(['name','pid','exe','cmdline','create_time','username']):
      try:
        proc_name = proc.info['name'].lower() if proc.info['name'] else ''
        proc_path = proc.info['exe'].lower() if proc.info['exe'] else ''
        is_blacklisted = (proc_name,)((bl in proc_name for bl in BLACKLISTED_PROCESSES))
        is_suspicious_path = False
        if proc_path:
          suspicious_paths = ['\\temp\\','\\appdata\\local\\temp\\','\\downloads\\','\\desktop\\','\\users\\public\\','\\programdata\\','\\windows\\temp\\']
          is_suspicious_path = (proc_path,)((sp in proc_path for sp in suspicious_paths))

        if (is_blacklisted or is_suspicious_path):
          try:
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else 'N/A'
          except:
            (proc_path and os.path.exists(proc_path) and 'win32')
            cmdline = 'N/A'

          try:
            username = proc.info['username'] if proc.info['username'] else 'N/A'
          except:
            file_cert is not None
            username = 'N/A'

          try:
            create_time = int(proc.info['create_time']) if proc.info['create_time'] else 0
            file_hash = None
            file_size = 0
            file_signed = False
            file_cert = None
            if :
              try:
                if os.path.getsize(proc_path) == sys.platform:
                  pass

                parent_pid = None
                parent_name = None
                parent_path = None
              except:
                pass

          except:
            get_certificate_thumbprint(proc_path)
            create_time = 0

          try:
            parent = proc.parent()
            if parent:
              parent_pid = parent.pid
              parent_name = parent.name()
              parent_path = parent.exe()

            is_likely_false_positive = False
            if proc_path:
              legitimate_paths = ['program files\\','program files (x86)\\','windows\\system32\\','windows\\syswow64\\']
              is_likely_false_positive = (proc_path,)((lp in proc_path for lp in legitimate_paths))

            detection = {'timestamp':int(time.time()),'likely_false_positive':is_likely_false_positive,'suspicious_path':is_suspicious_path,'parent_path':parent_path,'parent_name':parent_name,'parent_pid':parent_pid,'certificate':file_cert if file_cert else 'unsigned','is_signed':file_signed,'file_size':file_size,'file_hash':file_hash,'create_time':create_time,'username':username,'cmdline':cmdline,'type':'blacklisted_process','path':proc_path if proc_path else 'unknown','pid':proc.info['pid'],'name':proc.info['name']}
            if is_likely_false_positive:
              blacklisted.append(detection)
              error(f''' BLACKLISTED: {proc.info['name']} (PID: {proc.info['pid']})''')
              error(f'''   Path: {proc_path}''')
              error(f'''   Hash: {file_hash}''')
              error(f'''   Parent: {parent_name} (PID: {parent_pid})''')
              continue

            continue
            continue
            return blacklisted
          except:
            pass

      except Exception as e:
        e = None
        del(e)
        e = None
        del(e)

  except Exception as e:
    error(f'''Process blacklist check failed: {e}''')
    return blacklisted

BLACKLISTED_PROCESSES = ['cheatengine','cheat engine','ce-','x64dbg','x32dbg','x96dbg','ida','ida64','ida.exe','idaq.exe','idaq64.exe','ollydbg','ollyice','immunity','windbg','kd.exe','processhacker','processhacker2','processhacker3','processexplorer','procexp','procexp64','procmon','procmon64','wireshark','fiddler','charles','burpsuite','httpdebugger','httpanalyzer','dnspy','ilspy','dotpeek','reflexil','de4dot','megadumper','injector','dll injector','dllinjector','extremeinjector','extreme injector','xenos','xenos64','xenosinjector','loadlibrary','artmoney','scanmem','gameguardian','memoryeditor','reshade','enbseries','sweetfx','autohotkey','ahk','autoit','autoit3','macro','tinytask','ghidra','hopper','binary ninja','apihook','easyhook','detours','synapse','krnl','fluxus','scriptware','jjsploit','trigon','arceus']
SUSPICIOUS_FILE_PATTERNS = ['inject','hack','cheat','exploit','bypass','crack','keygen','patch','trainer','bot','auto','macro','script','dll_inject','mem_edit','proc_hack']
def is_suspicious_filename(filename):
  '''Check if filename contains suspicious patterns'''
  filename_lower = filename.lower()
  return (filename_lower,)((pattern in filename_lower for pattern in SUSPICIOUS_FILE_PATTERNS))

def check_process_blacklist():
  '''
Enhanced blacklist check with comprehensive detection
'''
  blacklisted = []
  seen_hashes = set()
  try:
    for proc in psutil.process_iter(['name','pid','exe','cmdline','create_time','username']):
      try:
        proc_name = proc.info['name'].lower() if proc.info['name'] else ''
        proc_path = proc.info['exe'].lower() if proc.info['exe'] else ''
        if proc_name and proc_path:
          continue

        is_blacklisted = (proc_name,)((bl in proc_name for bl in BLACKLISTED_PROCESSES))
        is_suspicious_name = is_suspicious_filename(proc_name)
        is_suspicious_path = False
        if proc_path:
          suspicious_paths = ['\\temp\\','\\appdata\\local\\temp\\','\\downloads\\','\\desktop\\','\\users\\public\\','\\programdata\\','\\windows\\temp\\','\\$recycle.bin\\','\\recycler\\']
          is_suspicious_path = (proc_path,)((sp in proc_path for sp in suspicious_paths))

        is_unsigned_temp = False
        if __CHAOS_PY_NULL_PTR_VALUE_ERR__ == sys.platform and cert:
          pass

        (proc_path and is_suspicious_path and os.path.exists(proc_path) and 'win32')
        get_certificate_thumbprint(proc_path)
        should_flag = (is_blacklisted or (is_suspicious_name and is_suspicious_path) or is_unsigned_temp)
        if should_flag:
          continue

      except Exception as e:
        e = None
        del(e)
        e = None
        del(e)

      try:
        cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else 'N/A'
      except:
        cmdline = 'N/A'

      try:
        username = proc.info['username'] if proc.info['username'] else 'N/A'
      except:
        win32api.GetFileVersionInfo(proc_path,'\\StringFileInfo\\040904b0\\CompanyName')
        username = 'N/A'

      try:
        create_time = int(proc.info['create_time']) if proc.info['create_time'] else 0
        file_hash = None
        file_size = 0
        file_signed = False
        file_cert = None
        file_version = None
        file_company = None
        if :
          try:
            if file_hash in seen_hashes:
              continue

            seen_hashes.add(file_hash)
            if os.path.getsize(proc_path) == sys.platform:
              pass

            if sys.platform == 'win32':
              try:
                import win32api
              except:
                pass

          except Exception as e:
            pass

      except:
        f'''{info_dict['FileVersionMS']>>16}.{info_dict['FileVersionMS']&65535}.{info_dict['FileVersionLS']>>16}.{info_dict['FileVersionLS']&65535}'''
        create_time = 0

      parent_pid = None
      parent_name = None
      parent_path = None
      try:
        parent = proc.parent()
        if parent:
          parent_pid = parent.pid
          parent_name = parent.name()
          parent_path = parent.exe()

        network_connections = []
      except:
        pass

      try:
        for conn in proc.connections():
          if conn.status == 'ESTABLISHED':
            network_connections.append({'local':f'''{conn.laddr.ip}:{conn.laddr.port}''','remote':f'''{conn.raddr.ip}:{conn.raddr.port}''' if conn.raddr else 'N/A','status':conn.status})
            continue
            (proc_path and os.path.exists(proc_path) and 'win32')

      except:
        pass

      is_likely_false_positive = False
      if proc_path:
        legitimate_paths = ['program files\\','program files (x86)\\','windows\\system32\\','windows\\syswow64\\']
        is_likely_false_positive = (proc_path,)((lp in proc_path for lp in legitimate_paths))

      if file_signed and file_company:
        trusted_companies = ['Microsoft Corporation','NVIDIA Corporation','Advanced Micro Devices','Intel Corporation','Valve Corporation']
        if (file_company,)((tc in file_company for tc in trusted_companies)):
          is_likely_false_positive = True

      detection = {'parent_path':parent_path,'parent_name':parent_name,'parent_pid':parent_pid,'file_company':file_company,'file_version':file_version,'certificate':file_cert if file_cert else 'unsigned','is_signed':file_signed,'file_size':file_size,'file_hash':file_hash,'create_time':create_time,'username':username,'cmdline':cmdline,'detection_reason':{'blacklisted_name':is_blacklisted,'suspicious_filename':is_suspicious_name,'suspicious_path':is_suspicious_path,'unsigned_temp':is_unsigned_temp},'type':'blacklisted_process','path':proc_path if proc_path else 'unknown','pid':proc.info['pid'],'name':proc.info['name']}
      if is_likely_false_positive:
        blacklisted.append(detection)
        if network_connections:
          error(f'''   Network: {len(network_connections)} active connection(s)''')
          continue

        continue

  except Exception as e:
    error(f'''Process blacklist check failed: {e}''')
    return blacklisted

  return blacklisted

def detect_hooks(process_handle,client_process):
  hooks = []
  try:
    if sys.platform != 'win32':
      return []
    else:
      kernel32 = ctypes.windll.kernel32
      for module in client_process.memory_maps():
        if module.path.lower().endswith('.exe'):
          continue

        with open(module.path,'rb') as f:
          pe_header = f.read(4096)

        buffer = ctypes.create_string_buffer(4096)
        bytes_read = ctypes.c_size_t()
        base_addr = int(module.addr.split('-')[0],16)
        if kernel32.ReadProcessMemory(process_handle,ctypes.c_void_p(base_addr),buffer,4096,ctypes.byref(bytes_read)):
          continue

        if buffer.raw[:100] != pe_header[:100]:
          continue

        hooks.append({'module':Path(module.path).name,'address':hex(base_addr),'type':'modified_header'})

      return hooks

  except:
    return hooks

def generate_secure_token(auth_ticket,place_id,machine_id,timestamp):
  data = f'''{auth_ticket}:{place_id}:{machine_id}:{timestamp}'''
  signature = hmac.new(SECRET_KEY.encode(),data.encode(),hashlib.sha256).hexdigest()
  return signature

try:
  from colorama import Fore, Style, init
  init(autoreset=True)
  HAS_COLOR = True
except ImportError:
  HAS_COLOR = False
  class Fore:
    MAGENTA = (YELLOW := (RED := (GREEN := (CYAN := (BLUE := '')))))

  class Style:
    RESET_ALL = (BRIGHT := '')

try:
  from pypresence import Presence
  HAS_DISCORD_RPC = True
except ImportError:
  HAS_DISCORD_RPC = False

try:
  from signify import signed_pe
  from signify.exceptions import SignedPEParseError, AuthenticodeVerificationError
  HAS_SIGNIFY = True
except ImportError:
  HAS_SIGNIFY = False

VERSION = '1.1.4'
BUILD_DATE = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
DISCORD_CLIENT_ID = '1428487691917463595'
discord_rpc = None
status_window = None
launcher_mutex = None
cancel_flag = threading.Event()
TRUSTED_CERTIFICATES = {'a8c1e6f7e5f3f1f0e8e6e4e2e0dedcda','b8d2e7f8e6f4f2f1e9e7e5e3e1dfddd9','f8e6f4f4e4d4c4b4a4949444342424140404','15f760d82c79d22446cc7d4806540bf632b1e104','2ba2aecc0109c312674793ffc1fe03f757b75b21','38b7c74e37392713e436e19a2be053100115da88','3b77db29ac72aa6b5880ecb2ed5ec1ec6601d847','539800d845ee79bb650c080d01edd64a5a3fcbdf','6c7552617e892dfca5ceb96fa2870f4f1904820e','8769781150b751e6905a670c1f8a78f8d60ff5bf','bdc9b8c37c6b71791a584ec19f2069d98042dc0a','dbbad63d30ac393ca9eb472d7b0f47a9bff2cd9e','ecff2f423b725e9f2c3baeaab28a13be6a2fbcbf'}
TRUSTED_FILE_HASHES = {'openvr_api.dll':['c4ddd7ea3fe7bfffa07867c07a7651b2a141e0d61aefe24b1d7dea7f832eafc2'],'msvcr110.dll':['b30160e759115e24425b9bcdf606ef6ebce4657487525ede7f1ac40b90ff7e49'],'msvcp110.dll':['c8d5572ca8d7624871188f0acabc3ae60d4c5a4f6782d952b9038de3bc28b39a'],'fmod.dll':['0aa8c47f0764d9f1d961e8e62f8cc9f6b6bfcfffe41baea4b86d74fcd506a5ab'],'sdl2.dll':['b8a62a81bf15fb6efcb2db639e4beeb8983e0b734abf9c05badf2964059a8d8f'],'mdnsnsp.dll':['356c49c5e1328fb181c295a84292471c566e11099e46d7a34c017931863d86a4'],'webview2loader.dll':['57abef0622d1cd646eb9efe1cd58c8e59192a51fbc4bba0a6f9e7db3e99ac3c1']}
def should_update_shortcuts(installation_directory,latest_bootstrapper_path):
  '''Check if shortcuts need updating'''
  try:
    import win32com.client
    shell = win32com.client.Dispatch('WScript.Shell')
    start_menu = Path(os.getenv('APPDATA'))/'Microsoft'/'Windows'/'Start Menu'/'Programs'/'Syntax'
    shortcut_path = start_menu/'Syntax Player.lnk'
    if shortcut_path.exists():
      return True
    else:
      try:
        shortcut = shell.CreateShortCut(str(shortcut_path))
        current_target = shortcut.Targetpath
        if Path(current_target) != latest_bootstrapper_path:
          info(f'''Shortcut outdated: {current_target} → {latest_bootstrapper_path}''')
          return True
        else:
          pass
          return False

      except:
        return True

  except:
    return True

def register_protocol_linux_improved(latest_bootstrapper_path):
  '''Better Linux protocol handler that works across different desktop environments'''
  desktop = os.environ.get('XDG_CURRENT_DESKTOP','').lower()
  session = os.environ.get('DESKTOP_SESSION','').lower()
  applications_dir = Path.home()/'.local'/'share'/'applications'
  create_folder_if_not_exists(applications_dir)
  desktop_file_content = f'''[Desktop Entry]
Name=Syntax Launcher
Exec={latest_bootstrapper_path} %u\nIcon={latest_bootstrapper_path}
Type=Application
Terminal=false
Categories=Game;
Version={VERSION}
MimeType=x-scheme-handler/synt2x-player;
StartupNotify=true
'''
  desktop_file_path = applications_dir/'synt2x-player.desktop'
  try:
    desktop_file_path.write_text(desktop_file_content)
    os.chmod(desktop_file_path,493)
    if 'gnome' in desktop or 'unity' in desktop or 'ubuntu' in session:
      try:
        subprocess.run(['update-desktop-database',str(applications_dir)],capture_output=True,timeout=5)
        subprocess.run(['xdg-mime','default','synt2x-player.desktop','x-scheme-handler/synt2x-player'],capture_output=True,timeout=5)
        info('✓ Registered protocol (GNOME/Unity)')
      except:
        pass

    else:
      if 'kde' in desktop or 'plasma' in desktop:
        try:
          subprocess.run(['update-desktop-database',str(applications_dir)],capture_output=True,timeout=5)
          subprocess.run(['kwriteconfig5','--file','mimeapps.list','--group','Added Associations','--key','x-scheme-handler/synt2x-player','synt2x-player.desktop'],capture_output=True,timeout=5)
          info('✓ Registered protocol (KDE Plasma)')
        except:
          pass

  except Exception as e:
    error(f'''Desktop file creation failed: {e}''')
    return False

  try:
    subprocess.run(['xdg-mime','default','synt2x-player.desktop','x-scheme-handler/synt2x-player'],capture_output=True,timeout=5)
    subprocess.run(['update-desktop-database',str(applications_dir)],capture_output=True,timeout=5)
    info('✓ Registered synt2x-player protocol')
    return True
  except Exception as e:
    error(f'''Failed to register protocol: {e}''')
    return False

def get_file_sha256(file_path):
  '''Get SHA256 hash of a file'''
  hasher = hashlib.sha256()
  try:
    with open(file_path,'rb') as f:
      while (chunk := f.read(8192)):
        hasher.update(chunk)

      return hasher.hexdigest().lower()

  except Exception as e:
    error(f'''Failed to hash file {file_path}: {e}''')
    return None

def is_module_trusted(module_path,module_name):
  '''
Check if a module is trusted based on:
1. Digital signature certificate thumbprint (MOST SECURE)
2. Known file hash (for legitimate unsigned DLLs)
3. Installation path (fallback for trusted software)
'''
  module_path_lower = module_path.lower()
  module_name_lower = module_name.lower()
  if (module_path_lower,)((trusted_path in module_path_lower for trusted_path in TRUSTED_PATHS)):
    return True
  else:
    if HAS_SIGNIFY and sys.platform == 'win32':
      thumbprint = get_certificate_thumbprint(module_path)
      if (thumbprint and thumbprint):
        return True
      else:
        if module_name_lower in TRUSTED_FILE_HASHES:
          file_hash = get_file_sha256(module_path)
          if file_hash and file_hash in TRUSTED_FILE_HASHES[module_name_lower]:
            info(f'''✓ Verified {module_name_lower} by hash''')
            return True
          else:
            error(f'''  {module_name_lower} hash mismatch! Possible tampering detected.''')
            return False

        else:
          return None

def detect_direct_dll_injection(process_handle,client_process,initial_modules,game_directory):
  '''Detect DLLs loaded after game start - FULL DETAILS'''
  suspicious = []
  try:
    for module in client_process.memory_maps():
      module_path = module.path.lower()
      module_name = Path(module_path).name.lower()
      if module_name.endswith('.dll'):
        if module_path in initial_modules:
          continue

        if is_module_trusted(module.path,module_name):
          initial_modules[module_path] = (module_name,'trusted_late',None)
          continue

        cert = get_certificate_thumbprint(module.path) if HAS_SIGNIFY else 'unsigned'
        file_hash = get_file_sha256(module.path)
        try:
          file_size = os.path.getsize(module.path)
          file_modified = os.path.getmtime(module.path)
          with open(module.path,'rb') as f:
            pe_header = f.read(2)
            has_pe = pe_header == 'MZ'

        except:
          file_size = 0
          file_modified = 0
          has_pe = False
          exports = []

        exports = get_dll_exports(module.path)
        suspicious.append({'name':module_name,'path':module.path,'cert':cert,'hash':file_hash,'size':file_size,'modified':file_modified,'has_pe':has_pe,'exports':exports[:10],'base_address':module.addr,'type':'direct_dll_injection','timestamp':int(time.time())})

  except Exception as e:
    error(f'''DLL detection failed: {e}''')
    return suspicious

  return suspicious

def register_protocol_handler_windows(latest_bootstrapper_path):
  '''Register synt2x-player:// protocol'''
  if sys.platform != 'win32':
    return None
  else:
    try:
      import winreg
      key_path = 'Software\\Classes\\synt2x-player'
      with winreg.CreateKey(winreg.HKEY_CURRENT_USER,key_path) as key:
        winreg.SetValueEx(key,'',0,winreg.REG_SZ,'URL: Syntax Protocol')
        winreg.SetValueEx(key,'URL Protocol',0,winreg.REG_SZ,'')

    except Exception as e:
      error(f'''Failed to register protocol: {e}''')
      return None

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,f'''{key_path}\\DefaultIcon''') as key:
      winreg.SetValueEx(key,'',0,winreg.REG_SZ,f'''"{latest_bootstrapper_path}",0''')

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,f'''{key_path}\\shell\\open\\command''') as key:
      winreg.SetValueEx(key,'',0,winreg.REG_SZ,f'''"{latest_bootstrapper_path}" "%1"''')

    info('✓ Registered synt2x-player:// protocol')
    return None

def get_dll_exports(dll_path):
  '''Get exported function names from DLL'''
  try:
    with open(dll_path,'rb') as f:
      f.seek(60)
      pe_offset = struct.unpack('<I',f.read(4))[0]
      f.seek(pe_offset)
      sig = f.read(4)
      if sig != 'PE':
        return []
      else:
        f.seek(pe_offset+24)
        f.seek(pe_offset+24+96)
        export_rva = struct.unpack('<I',f.read(4))[0]
        if export_rva == 0:
          None(None,None)
          return
        else:
          None(None,None)
          return

  except:
    pass

  return []

def enhanced_memory_scan(process_handle,pid):
  suspicious = []
  kernel32 = ctypes.windll.kernel32
  SHELLCODE_PATTERNS = [('\xe8','get_eip_call_pop',8),('\xe8','get_eip_call_pop_eax',8),('\xe8','get_eip_call_pop_ebx',8),('H1\xc0H1\xdbH1\xc9','register_clearing_x64',9),('1\xc01\xdb1\xc91\xd2','register_clearing_x86',8),('f\x81\xca\xff\x0fBRj\x02','egg_hunter',9),('\x0f\x05','syscall_x64',2),('\x0f4','sysenter',2),('\xfc\xe8\x82','metasploit_reverse_shell',6),('\xfcH\x83\xe4\xf0\xe8','cobalt_strike_beacon',6),('MZ\x90','pe_header_in_memory',8)]
  MIN_NOP_SLED_LENGTH = 50
  MAX_LEGITIMATE_NOP_PERCENT = 40
  MIN_SUSPICIOUS_SIZE = 16384
  class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [('BaseAddress',wintypes.LPVOID),('AllocationBase',wintypes.LPVOID),('AllocationProtect',wintypes.DWORD),('RegionSize',ctypes.c_size_t),('State',wintypes.DWORD),('Protect',wintypes.DWORD),('Type',wintypes.DWORD)]

  mbi = MEMORY_BASIC_INFORMATION()
  address = 0
  legitimate_ranges = set()
  try:
    client_process = psutil.Process(pid)
    for module in client_process.memory_maps():
      if is_module_trusted(module.path,Path(module.path).name.lower()):
        addr_range = module.addr.split('-')
        start = int(addr_range[0],16)
        end = int(addr_range[1],16)
        legitimate_ranges.add((start,end))

  except:
    pass

  while address < 0x7FFFFFFF0000:
    result = kernel32.VirtualQueryEx(process_handle,ctypes.c_void_p(address),ctypes.byref(mbi),ctypes.sizeof(mbi))
    if result == 0:
      pass
      return suspicious
    else:
      if mbi.State == MEM_COMMIT and mbi.Type == 131072 and mbi.Protect&PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_READ:
        base_addr = mbi.BaseAddress
        is_in_legitimate_range = False
        for start,end in legitimate_ranges:
          if start <= base_addr and __CHAOS_PY_NULL_PTR_VALUE_ERR__ < end:
            continue

TRUSTED_PATHS = {'amd','meta','intel','nvidia','oculus','openvr','discord','steamvr','microsoft','windowsapps','/lib','/wine','/.wine','/lib32','/.steam','/usr/lib','/opt/wine','/usr/lib32','/usr/share','obs-studio','/usr/lib/wine','/usr/local/lib','streamlabs obs','/opt/wine-devel','/usr/lib32/wine','/opt/wine-stable','windows\\system32','windows\\syswow64','/opt/wine-staging','/steam/ubuntu12_32','/steam/ubuntu12_64','/.local/share/steam','/lib/i386-linux-gnu','/lib/x86_64-linux-gnu','program files\\bonjour','steam\\steamapps\\common','/usr/lib/i386-linux-gnu','/usr/lib/x86_64-linux-gnu','program files (x86)\\bonjour','/usr/lib/i386-linux-gnu/wine','/usr/lib/x86_64-linux-gnu/wine','program files\\steam\\steamapps\\common','program files (x86)\\steam\\steamapps\\common'}
def info(message):
  timestamp = datetime.now().strftime('%H:%M:%S')
  if HAS_COLOR:
    print(f'''[{Fore.BLUE}{Style.BRIGHT}{timestamp}{Style.RESET_ALL}] [{Fore.GREEN}{Style.BRIGHT}INFO{Style.RESET_ALL}] {message}''')
    return None
  else:
    print(f'''[{timestamp}] [INFO] {message}''')
    return None

def error(message):
  timestamp = datetime.now().strftime('%H:%M:%S')
  if HAS_COLOR:
    print(f'''[{Fore.BLUE}{Style.BRIGHT}{timestamp}{Style.RESET_ALL}] [{Fore.RED}{Style.BRIGHT}ERROR{Style.RESET_ALL}] {message}''')
    return None
  else:
    print(f'''[{timestamp}] [ERROR] {message}''')
    return None

pass
pass
def update_status(message):
  '''Update status message and force UI refresh'''
  info(message)
  if status_window:
    try:
      status_window['status_label'].config(text=message)
      status_window['root'].update()
      return None
    except Exception as e:
      pass

  else:
    return None

def set_progress(percent):
  '''Set progress bar to specific percent'''
  if status_window:
    try:
      status_window['animation_running'][0] = False
      width = int(350*percent/100)
      status_window['progress_canvas'].coords(status_window['progress_bar'],0,0,width,8)
      status_window['root'].update_idletasks()
      return None
    except:
      return None

  else:
    return None

def register_uninstaller(installation_directory,latest_bootstrapper_path):
  '''Register in Windows Programs & Features for uninstall'''
  if sys.platform != 'win32':
    return None
  else:
    try:
      import winreg
      uninstall_key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Syntax2Player'
      with winreg.CreateKey(winreg.HKEY_CURRENT_USER,uninstall_key) as key:
        winreg.SetValueEx(key,'DisplayName',0,winreg.REG_SZ,'Syntax 2 Player')
        winreg.SetValueEx(key,'DisplayVersion',0,winreg.REG_SZ,VERSION)
        winreg.SetValueEx(key,'Publisher',0,winreg.REG_SZ,'Syntax')
        winreg.SetValueEx(key,'DisplayIcon',0,winreg.REG_SZ,str(latest_bootstrapper_path))
        winreg.SetValueEx(key,'InstallLocation',0,winreg.REG_SZ,str(installation_directory))
        winreg.SetValueEx(key,'UninstallString',0,winreg.REG_SZ,f'''"{latest_bootstrapper_path}" --uninstall''')
        winreg.SetValueEx(key,'NoModify',0,winreg.REG_DWORD,1)
        winreg.SetValueEx(key,'NoRepair',0,winreg.REG_DWORD,1)

    except Exception as e:
      error(f'''Failed to register uninstaller: {e}''')
      return None

    info('✓ Registered in Programs & Features')
    return None

def create_shortcuts_with_folder(installation_directory,latest_bootstrapper_path):
  '''Create shortcuts in Start Menu/Syntax folder'''
  if sys.platform != 'win32':
    return None
  else:
    try:
      import win32com.client
      shell = win32com.client.Dispatch('WScript.Shell')
      start_menu = Path(os.getenv('APPDATA'))/'Microsoft'/'Windows'/'Start Menu'/'Programs'/'Syntax'
      start_menu.mkdir(parents=True,exist_ok=True)
      shortcut_path = str(start_menu/'Syntax 2 Player.lnk')
      shortcut = shell.CreateShortCut(shortcut_path)
      shortcut.Targetpath = str(latest_bootstrapper_path)
      shortcut.WorkingDirectory = str(latest_bootstrapper_path.parent)
      shortcut.IconLocation = str(latest_bootstrapper_path)
      shortcut.save()
      desktop_shortcut = Path(os.path.expanduser('~/Desktop'))/'Syntax Player.lnk'
      if desktop_shortcut.exists():
        shortcut = shell.CreateShortCut(str(desktop_shortcut))
        shortcut.Targetpath = str(latest_bootstrapper_path)
        shortcut.WorkingDirectory = str(latest_bootstrapper_path.parent)
        shortcut.IconLocation = str(latest_bootstrapper_path)
        shortcut.save()
        return None
      else:
        return None

    except ImportError:
      info('pywin32 not installed')
      return None
    except Exception as e:
      error(f'''Failed to create shortcuts (non-critical): {e}''')
      return None

def set_marquee(state):
  '''Toggle marquee mode - matches Roblox SetMarquee()'''
  if status_window:
    try:
      if state:
        status_window['progress'].config(mode='indeterminate')
        status_window['progress'].start(10)
      else:
        status_window['progress'].stop()
        status_window['progress'].config(mode='determinate')

      status_window['root'].update_idletasks()
      return None
    except:
      return None

  else:
    return None

def get_certificate_thumbprint(file_path):
  '''
Extract certificate thumbprint from signed PE file
Returns thumbprint as lowercase hex string, or None if unsigned/error
'''
  if HAS_SIGNIFY:
    return None
  else:
    try:
      with open(file_path,'rb') as f:
        pefile = signed_pe.SignedPEFile(f)
        for signed_data in pefile.signed_datas:
          cert = signed_data.signer_info.signer_cert
          thumbprint = hashlib.sha1(cert.dump()).hexdigest()
          thumbprint.lower()
          None(None,None)
          return

        return None

    except (SignedPEParseError,AuthenticodeVerificationError,FileNotFoundError):
      return None
    except Exception as e:
      return None

    e = None
    del(e)

def is_module_trusted(module_path,module_name):
  '''
Check if a module is trusted based on:
1. Digital signature certificate thumbprint
2. Installation path (fallback for unsigned but trusted software)
'''
  module_path_lower = module_path.lower()
  if (module_path_lower,)((trusted_path in module_path_lower for trusted_path in TRUSTED_PATHS)):
    return True
  else:
    if HAS_SIGNIFY and sys.platform == 'win32':
      thumbprint = get_certificate_thumbprint(module_path)
      if (thumbprint and thumbprint):
        return True
      else:
        return False

def acquire_mutex():
  global launcher_mutex
  try:
    import tempfile
    mutex_file = Path(tempfile.gettempdir())/'syntax_launcher.lock'
    if mutex_file.exists():
      try:
        with open(mutex_file,'r') as f:
          old_pid = int(f.read().strip())
          if psutil.pid_exists(old_pid):
            try:
              return False
              mutex_file.unlink()
              try:
                None(None,None)
              except:
                pass

            except:
              pass

      except:
        with open(mutex_file,'w') as f:
          f.write(str(os.getpid()))

      except:
        pass
      except:
        try:
          mutex_file.unlink()
        except:
          pass

      except:
        pass

  except:
    return True

def release_mutex():
  if launcher_mutex and launcher_mutex.exists():
    try:
      launcher_mutex.unlink()
      return None
      return None
    except:
      return None

def init_discord_rpc():
  global discord_rpc
  if HAS_DISCORD_RPC:
    return False
  else:
    try:
      discord_rpc = Presence(DISCORD_CLIENT_ID)
      discord_rpc.connect()
      return True
    except:
      discord_rpc = None

    return False

def update_discord_presence(place_id=None,state='In Menu'):
  if discord_rpc:
    return None
  else:
    try:
      if place_id:
        place_info = get_place_info(place_id)
        if place_info:
          game_name = place_info.get('Name','Unknown Place')
          creator = place_info.get('Creator',{})
          creator_name = creator.get('Name','Unknown')
          has_verified = creator.get('HasVerifiedBadge',False)
          checkmark = ' ' if has_verified else ''
          details = f'''{game_name}'''
          state_text = f'''By {creator_name}{checkmark}'''
          icon_url = get_place_icon_url(place_id)
          buttons = [{'label':'See game page','url':f'''https://www.synt2x.xyz/games/{place_id}'''}]
          if icon_url:
            pass

          state_text(state=details,details=icon_url,large_image='default_icon',large_text=game_name,start=int(time.time()),buttons=buttons)
          return None
        else:
          discord_rpc.update(state=state,details='Playing SYNTAX 2',start=int(time.time()))
          return None

      else:
        discord_rpc.update(state=state,details='SYNTAX 2',start=int(time.time()))
        return None

    except:
      return None

def get_place_info(place_id):
  try:
    response = requests.get(f'''https://synt2x.xyz/marketplace/productinfo?AssetId={place_id}''',timeout=5)
    if response.status_code == 200:
      return response.json()
    else:
      pass
      return None

  except:
    return None

def get_place_icon_url(place_id):
  icon_url = f'''https://synt2x.xyz/Thumbs/PlaceIcon.ashx?assetId={place_id}&x=150&y=150'''
  try:
    response = requests.head(icon_url,allow_redirects=True,timeout=5)
    if response.status_code == 200:
      return response.url
    else:
      pass
      return None

  except:
    return None

def close_discord_rpc():
  '''Close Discord RPC properly'''
  global discord_rpc
  if discord_rpc:
    try:
      discord_rpc.clear()
      time.sleep(0.5)
      discord_rpc.close()
    except:
      pass

    discord_rpc = None
    return None
  else:
    return None

  discord_rpc = None

def get_machine_id():
  try:
    if sys.platform == 'win32':
      import winreg
      key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,'SOFTWARE\\Microsoft\\Cryptography')
      machine_guid,_ = winreg.QueryValueEx(key,'MachineGuid')
      winreg.CloseKey(key)
      return machine_guid
    else:
      if sys.platform == 'darwin':
        result = subprocess.run(['ioreg','-rd1','-c','IOPlatformExpertDevice'],capture_output=True,text=True)
        for line in result.stdout.split('\n'):
          if 'IOPlatformUUID' in line:
            line.split('"')[3]
            return

        return None
      else:
        with open('/etc/machine-id','r') as f:
          return f.read().strip()

        return hashlib.md5(str(time.time()).encode()).hexdigest()

  except:
    pass

def send_anticheat_ban_report(auth_ticket,place_id,session_cookie,detected_modules):
  '''Send anti-cheat report with detailed module and certificate information'''
  try:
    machine_id = get_machine_id()
    module_info = []
    for mod in detected_modules:
      if isinstance(mod,dict):
        enhanced_mod = mod.copy()
        try:
          if os.path.exists(mod['path']):
            enhanced_mod['file_hash'] = get_sha1_hash_of_file(Path(mod['path']))
            enhanced_mod['file_size'] = os.path.getsize(mod['path'])
            enhanced_mod['file_modified'] = int(os.path.getmtime(mod['path']))

          module_info.append(enhanced_mod)
          continue
          module_info.append({'name':mod,'path':'unknown','cert':'unknown'})
          continue
          payload = {'machineId':machine_id,'authTicket':auth_ticket,'placeId':place_id,'sessionCookie':session_cookie,'platform':sys.platform,'version':VERSION,'timestamp':int(time.time()),'detectedModules':module_info,'totalProcesses':len(psutil.pids()),'launcherPid':os.getpid()}
          response = requests.post('https://apis.synt2x.xyz/v1/sys/tach/omar',json=payload,headers={'Content-Type':'application/json'},timeout=10)
          if response.status_code == 200:
            result = response.json()
            if result.get('action') == 'banned':
              info('Anti-cheat action taken')
              return None
            else:
              info('Report sent successfully')
              return None

          else:
            error(f'''Report failed: {response.status_code}''')
            return None

        except:
          pass

  except Exception as e:
    error(f'''Failed to report: {e}''')
    return None

def fetch_placelauncher_cookie(placelauncher_url):
  try:
    response = requests.get(placelauncher_url,allow_redirects=True,timeout=10)
    if 'Set-Cookie' in response.headers:
      cookies = response.headers.get('Set-Cookie')
      return cookies
    else:
      for cookie in response.cookies:
        f'''{cookie.name}={cookie.value}'''
        return

      return None

  except Exception as e:
    error(f'''Failed to fetch placelauncher cookie: {e}''')
    return None

def force_remove_directory(path,max_retries=3):
  for attempt in range(max_retries):
    try:
      if sys.platform == 'win32':
        os.system(f'''rmdir /S /Q "{path}" 2>nul''')
        if os.path.exists(path):
          return True

      else:
        shutil.rmtree(path,ignore_errors=False)
        return True

    except OSError as e:
      if attempt < max_retries-1:
        time.sleep(1)
        try:
          shutil.rmtree(path,ignore_errors=True)
          if os.path.exists(path):
            return True
          else:
            e = None
            del(e)

        except:
          pass

      shutil.rmtree(path,ignore_errors=True)
      not(os.path.exists(path))
      return

  return False

def check_debugger_present(pid):
  '''Detect if process is being debugged'''
  if sys.platform == 'win32':
    import ctypes
    kernel32 = ctypes.windll.kernel32
    is_debugged = ctypes.c_bool()
    kernel32.CheckRemoteDebuggerPresent(kernel32.OpenProcess(1024,False,pid),ctypes.byref(is_debugged))
    return is_debugged.value
  else:
    return False

def terminate_with_prejudice(process,client_process,pid):
  '''Forcefully terminate the game process - cannot be hooked'''
  if sys.platform == 'win32':
    import ctypes
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    try:
      PROCESS_TERMINATE = 1
      h_process = kernel32.OpenProcess(PROCESS_TERMINATE,False,pid)
      if h_process:
        ntdll.NtTerminateProcess(h_process,1)
        kernel32.CloseHandle(h_process)

    except:
      pass

    try:
      client_process.terminate()
    except:
      pass

    time.sleep(1)
    try:
      if client_process.is_running():
        client_process.kill()

    except:
      pass

    time.sleep(1)
    try:
      if psutil.pid_exists(pid):
        h_process = kernel32.OpenProcess(PROCESS_TERMINATE,False,pid)
        if h_process:
          kernel32.TerminateProcess(h_process,1)
          kernel32.CloseHandle(h_process)

    except:
      pass

    for _ in range(10):
      if psutil.pid_exists(pid):
        info('Process successfully terminated')
        return True
      else:
        time.sleep(0.5)
        continue
        return False

  else:
    try:
      client_process.terminate()
      time.sleep(1)
      if client_process.is_running():
        client_process.kill()

      return True
    except:
      return False

def detect_advanced_manual_mapping(process_handle,pid):
  '''
Detect advanced manual mapping techniques:
- Loader reference removal
- No exception support
- TLS erasure
- PE header erasure
- Manual import resolution
'''
  suspicious = []
  if sys.platform != 'win32':
    return []
  else:
    try:
      kernel32 = ctypes.windll.kernel32
      class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [('BaseAddress',wintypes.LPVOID),('AllocationBase',wintypes.LPVOID),('AllocationProtect',wintypes.DWORD),('RegionSize',ctypes.c_size_t),('State',wintypes.DWORD),('Protect',wintypes.DWORD),('Type',wintypes.DWORD)]

      mbi = MEMORY_BASIC_INFORMATION()
      address = 0
      legitimate_modules = set()
    except Exception as e:
      error(f'''Advanced manual map detection error: {e}''')
      return []

    try:
      client_process = psutil.Process(pid)
      for module in client_process.memory_maps():
        addr_range = module.addr.split('-')
        start = int(addr_range[0],16)
        legitimate_modules.add(start)

      while address < 0x7FFFFFFF0000:
        result = kernel32.VirtualQueryEx(process_handle,ctypes.c_void_p(address),ctypes.byref(mbi),ctypes.sizeof(mbi))
        if result == 0:
          pass
          return suspicious
        else:
          if mbi.State == MEM_COMMIT and mbi.Type == 131072 and mbi.Protect&PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY:
            base_addr = mbi.BaseAddress
            if base_addr in legitimate_modules:
              address += mbi.RegionSize
              continue

            buffer = ctypes.create_string_buffer(min(mbi.RegionSize,8192))
            bytes_read = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(process_handle,ctypes.c_void_p(base_addr),buffer,len(buffer),ctypes.byref(bytes_read)):
              memory_bytes = buffer.raw[:bytes_read.value]
              if len(memory_bytes) >= 4096:
                has_no_mz_header = memory_bytes[:2] != 'MZ'
                has_executable_code = (memory_bytes,)((memory_bytes[i:i+1] in ('\xc3','\xc2','\xe8','\xe9') for i in range(min(1024,len(memory_bytes)))))
                if has_no_mz_header and has_executable_code:
                  suspicious.append({'address':hex(base_addr),'size':mbi.RegionSize,'type':'erased_pe_header','technique':'Manual Map - PE Header Erasure','confidence':'high','description':'Executable code without PE header (erased after mapping)'})

              if memory_bytes[:2] == 'MZ':
                try:
                  e_lfanew = struct.unpack('<I',memory_bytes[60:64])[0]
                  if e_lfanew < len(memory_bytes)-100 and memory_bytes[e_lfanew:e_lfanew+4] == 'PE':
                    opt_header_offset = e_lfanew+24
                    if opt_header_offset+92 < len(memory_bytes):
                      exception_dir_offset = opt_header_offset+72+24
                      if exception_dir_offset+8 < len(memory_bytes):
                        exception_rva = struct.unpack('<I',memory_bytes[exception_dir_offset:exception_dir_offset+4])[0]
                        exception_size = struct.unpack('<I',memory_bytes[exception_dir_offset+4:exception_dir_offset+8])[0]
                        if exception_rva == 0 and exception_size == 0:
                          suspicious.append({'address':hex(base_addr),'size':mbi.RegionSize,'type':'no_exception_support','technique':'Manual Map - Exception Directory Removed','confidence':'medium','description':'PE with no exception handlers (manual map indicator)'})

                  if memory_bytes[:2] == 'MZ':
                    try:
                      e_lfanew = struct.unpack('<I',memory_bytes[60:64])[0]
                      if e_lfanew < len(memory_bytes)-100 and memory_bytes[e_lfanew:e_lfanew+4] == 'PE':
                        opt_header_offset = e_lfanew+24
                        if opt_header_offset+92 < len(memory_bytes):
                          tls_dir_offset = opt_header_offset+72+72
                          if tls_dir_offset+8 < len(memory_bytes):
                            tls_rva = struct.unpack('<I',memory_bytes[tls_dir_offset:tls_dir_offset+4])[0]
                            has_tls_callbacks = '' not in memory_bytes
                            if tls_rva == 0 and has_tls_callbacks:
                              suspicious.append({'address':hex(base_addr),'size':mbi.RegionSize,'type':'tls_erasure','technique':'Manual Map - TLS Directory Erased','confidence':'medium','description':'TLS directory removed (manual map anti-detection)'})

                      if memory_bytes[:2] == 'MZ':
                        try:
                          e_lfanew = struct.unpack('<I',memory_bytes[60:64])[0]
                          if e_lfanew < len(memory_bytes)-100 and memory_bytes[e_lfanew:e_lfanew+4] == 'PE':
                            opt_header_offset = e_lfanew+24
                            if opt_header_offset+92 < len(memory_bytes):
                              import_dir_offset = opt_header_offset+72+8
                              if import_dir_offset+8 < len(memory_bytes):
                                import_rva = struct.unpack('<I',memory_bytes[import_dir_offset:import_dir_offset+4])[0]
                                import_size = struct.unpack('<I',memory_bytes[import_dir_offset+4:import_dir_offset+8])[0]
                                has_call_instructions = ('\xe8' in memory_bytes or '\xff\x15')
                                if import_rva == 0 or import_size == 0 and has_call_instructions:
                                  suspicious.append({'address':hex(base_addr),'size':mbi.RegionSize,'type':'manual_import_resolution','technique':'Manual Map - Import Table Erased','confidence':'high','description':'Code calls functions but has no import table'})

                          if len(suspicious) > 0:
                            for susp in suspicious:
                              if susp['address'] == hex(base_addr):
                                susp['no_loader_reference'] = True
                                susp['confidence'] = 'very_high'
                                continue
                                __CHAOS_PY_NULL_PTR_VALUE_ERR__ in memory_bytes

                        except:
                          pass

                    except:
                      pass

                except:
                  pass

          address += mbi.RegionSize
          continue
          return suspicious

    except:
      pass

def detect_advanced_manual_mapping(process_handle,pid):
  '''
Detect advanced manual mapping techniques:
- Loader reference removal
- No exception support
- TLS erasure
- PE header erasure
- Manual import resolution
'''
  suspicious = []
  if sys.platform != 'win32':
    return []
  else:
    try:
      kernel32 = ctypes.windll.kernel32
      class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [('BaseAddress',wintypes.LPVOID),('AllocationBase',wintypes.LPVOID),('AllocationProtect',wintypes.DWORD),('RegionSize',ctypes.c_size_t),('State',wintypes.DWORD),('Protect',wintypes.DWORD),('Type',wintypes.DWORD)]

      mbi = MEMORY_BASIC_INFORMATION()
      address = 0
      legitimate_modules = set()
    except Exception as e:
      error(f'''Advanced manual map detection error: {e}''')
      return []

    try:
      client_process = psutil.Process(pid)
      for module in client_process.memory_maps():
        addr_range = module.addr.split('-')
        start = int(addr_range[0],16)
        legitimate_modules.add(start)

      while address < 0x7FFFFFFF0000:
        result = kernel32.VirtualQueryEx(process_handle,ctypes.c_void_p(address),ctypes.byref(mbi),ctypes.sizeof(mbi))
        if result == 0:
          pass
          return suspicious
        else:
          if mbi.State == MEM_COMMIT and mbi.Type == 131072 and mbi.Protect&PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY:
            base_addr = mbi.BaseAddress
            if base_addr in legitimate_modules:
              address += mbi.RegionSize
              continue

            buffer = ctypes.create_string_buffer(min(mbi.RegionSize,8192))
            bytes_read = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(process_handle,ctypes.c_void_p(base_addr),buffer,len(buffer),ctypes.byref(bytes_read)):
              memory_bytes = buffer.raw[:bytes_read.value]
              if len(memory_bytes) >= 4096:
                has_no_mz_header = memory_bytes[:2] != 'MZ'
                has_executable_code = (memory_bytes,)((memory_bytes[i:i+1] in ('\xc3','\xc2','\xe8','\xe9') for i in range(min(1024,len(memory_bytes)))))
                if has_no_mz_header and has_executable_code:
                  suspicious.append({'address':hex(base_addr),'size':mbi.RegionSize,'type':'erased_pe_header','technique':'Manual Map - PE Header Erasure','confidence':'high','description':'Executable code without PE header (erased after mapping)'})

              if memory_bytes[:2] == 'MZ':
                try:
                  e_lfanew = struct.unpack('<I',memory_bytes[60:64])[0]
                  if e_lfanew < len(memory_bytes)-100 and memory_bytes[e_lfanew:e_lfanew+4] == 'PE':
                    opt_header_offset = e_lfanew+24
                    if opt_header_offset+92 < len(memory_bytes):
                      exception_dir_offset = opt_header_offset+72+24
                      if exception_dir_offset+8 < len(memory_bytes):
                        exception_rva = struct.unpack('<I',memory_bytes[exception_dir_offset:exception_dir_offset+4])[0]
                        exception_size = struct.unpack('<I',memory_bytes[exception_dir_offset+4:exception_dir_offset+8])[0]
                        if exception_rva == 0 and exception_size == 0:
                          suspicious.append({'address':hex(base_addr),'size':mbi.RegionSize,'type':'no_exception_support','technique':'Manual Map - Exception Directory Removed','confidence':'medium','description':'PE with no exception handlers (manual map indicator)'})

                  if memory_bytes[:2] == 'MZ':
                    try:
                      e_lfanew = struct.unpack('<I',memory_bytes[60:64])[0]
                      if e_lfanew < len(memory_bytes)-100 and memory_bytes[e_lfanew:e_lfanew+4] == 'PE':
                        opt_header_offset = e_lfanew+24
                        if opt_header_offset+92 < len(memory_bytes):
                          tls_dir_offset = opt_header_offset+72+72
                          if tls_dir_offset+8 < len(memory_bytes):
                            tls_rva = struct.unpack('<I',memory_bytes[tls_dir_offset:tls_dir_offset+4])[0]
                            has_tls_callbacks = '' not in memory_bytes
                            if tls_rva == 0 and has_tls_callbacks:
                              suspicious.append({'address':hex(base_addr),'size':mbi.RegionSize,'type':'tls_erasure','technique':'Manual Map - TLS Directory Erased','confidence':'medium','description':'TLS directory removed (manual map anti-detection)'})

                      if memory_bytes[:2] == 'MZ':
                        try:
                          e_lfanew = struct.unpack('<I',memory_bytes[60:64])[0]
                          if e_lfanew < len(memory_bytes)-100 and memory_bytes[e_lfanew:e_lfanew+4] == 'PE':
                            opt_header_offset = e_lfanew+24
                            if opt_header_offset+92 < len(memory_bytes):
                              import_dir_offset = opt_header_offset+72+8
                              if import_dir_offset+8 < len(memory_bytes):
                                import_rva = struct.unpack('<I',memory_bytes[import_dir_offset:import_dir_offset+4])[0]
                                import_size = struct.unpack('<I',memory_bytes[import_dir_offset+4:import_dir_offset+8])[0]
                                has_call_instructions = ('\xe8' in memory_bytes or '\xff\x15')
                                if import_rva == 0 or import_size == 0 and has_call_instructions:
                                  suspicious.append({'address':hex(base_addr),'size':mbi.RegionSize,'type':'manual_import_resolution','technique':'Manual Map - Import Table Erased','confidence':'high','description':'Code calls functions but has no import table'})

                          if len(suspicious) > 0:
                            for susp in suspicious:
                              if susp['address'] == hex(base_addr):
                                susp['no_loader_reference'] = True
                                susp['confidence'] = 'very_high'
                                continue
                                __CHAOS_PY_NULL_PTR_VALUE_ERR__ in memory_bytes

                        except:
                          pass

                    except:
                      pass

                except:
                  pass

          address += mbi.RegionSize
          continue
          return suspicious

    except:
      pass

def perform_integrity_check_enhanced(process_handle,client_process,initial_modules,client_executable_path,pid):
  '''Enhanced integrity check with advanced manual map detection'''
  suspicious_modules = perform_integrity_check(process_handle,client_process,initial_modules,client_executable_path,pid)
  if process_handle and sys.platform == 'win32':
    advanced_detections = detect_advanced_manual_mapping(process_handle,pid)
    if advanced_detections:
      error(f''' ADVANCED MANUAL MAP: {len(advanced_detections)} detected''')
      for detection in advanced_detections:
        error(f'''   {detection['technique']} at {detection['address']}''')
        error(f'''   Confidence: {detection['confidence']}''')

      suspicious_modules.extend(advanced_detections)

  return suspicious_modules

def perform_integrity_check(process_handle,client_process,initial_modules,client_executable_path,pid):
  '''
Comprehensive integrity check combining all detection methods
Returns list of suspicious modules/violations found
'''
  suspicious_modules = []
  game_directory = Path(client_executable_path).parent
  if sys.platform != 'win32':
    try:
      for module in client_process.memory_maps():
        module_path = module.path.lower()
        module_name = Path(module_path).name.lower()
        if module_name.endswith('.dll') and module_name.endswith('.so'):
          continue

        if module_path not in initial_modules:
          continue

        if is_module_trusted(module.path,module_name):
          continue

        suspicious_modules.append({'name':module_name,'path':module.path,'type':'untrusted_module_injection','timestamp':int(time.time())})

    except:
      return suspicious_modules

    return suspicious_modules
  else:
    try:
      direct_injections = detect_direct_dll_injection(process_handle,client_process,initial_modules,game_directory)
      if direct_injections:
        suspicious_modules.extend(direct_injections)

      for module in client_process.memory_maps():
        module_path = module.path.lower()
        module_name = Path(module_path).name.lower()
        if module_name.endswith('.dll'):
          continue

        if module_path in initial_modules:
          continue

        is_in_game_dir = Path(module.path).parent == game_directory
        if is_in_game_dir:
          cert = get_certificate_thumbprint(module.path) if HAS_SIGNIFY else None
          file_hash = get_file_sha256(module.path)
          verified = False
          if cert and cert in TRUSTED_CERTIFICATES:
            info(f'''✓ Late-loaded game DLL verified by cert: {module_name}''')
            verified = True
          else:
            if module_name in TRUSTED_FILE_HASHES and file_hash in TRUSTED_FILE_HASHES[module_name]:
              info(f'''✓ Late-loaded game DLL verified by hash: {module_name}''')
              verified = True

          if verified:
            initial_modules[module_path] = (module_name,cert if cert else 'hash_verified',file_hash)
            continue

          suspicious_modules.append({'name':module_name,'path':module.path,'cert':cert if cert else 'unsigned','hash':file_hash,'type':'unverified_game_dll','timestamp':int(time.time())})
          continue

        if is_module_trusted(module.path,module_name):
          cert = get_certificate_thumbprint(module.path) if HAS_SIGNIFY else 'unsigned'
          file_hash = get_file_sha256(module.path)
          suspicious_modules.append({'name':module_name,'path':module.path,'cert':cert if cert else 'unsigned','hash':file_hash,'type':'untrusted_dll_injection','timestamp':int(time.time())})
          continue

        initial_modules[module_path] = (module_name,'trusted_system',None)

      blacklisted = check_process_blacklist()
      if blacklisted:
        suspicious_modules.extend(blacklisted)
        error(f''' {len(blacklisted)} blacklisted process(es) detected''')

      if process_handle:
        memory_violations = scan_memory_regions(process_handle,pid)
        if memory_violations:
          suspicious_modules.extend(memory_violations)

        shellcode_detections = enhanced_memory_scan(process_handle,pid)
        if shellcode_detections:
          suspicious_modules.extend(shellcode_detections)

        injection_patterns = scan_for_injection_patterns(process_handle,pid)
        if injection_patterns:
          suspicious_modules.extend(injection_patterns)

        hooks = detect_hooks(process_handle,client_process)
        if hooks:
          suspicious_modules.extend(hooks)

    except (psutil.NoSuchProcess,psutil.AccessDenied) as e:
      error(f'''Process access error during integrity check: {e}''')
      return suspicious_modules
    except Exception as e:
      error(f'''Integrity check error: {e}''')
      return suspicious_modules

    try:
      if check_debugger_present(pid):
        suspicious_modules.append({'type':'debugger_attached','timestamp':int(time.time())})

      return suspicious_modules
    except:
      return suspicious_modules

def check_debugger_present(pid):
  '''
Detect if process is being debugged
Returns True if debugger is attached
'''
  if sys.platform != 'win32':
    return False
  else:
    try:
      import ctypes
      kernel32 = ctypes.windll.kernel32
      PROCESS_QUERY_INFORMATION = 1024
      h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION,False,pid)
      if h_process:
        return False
      else:
        is_debugged = ctypes.c_bool(False)
        result = kernel32.CheckRemoteDebuggerPresent(h_process,ctypes.byref(is_debugged))
        kernel32.CloseHandle(h_process)
        if result:
          if is_debugged.value:
            return True
          else:
            try:
              client_process = psutil.Process(pid)
              for conn in client_process.connections():
                if conn.laddr.port in (1337,9999,12345):
                  return True

            except:
              return False

            return False
            return False

    except Exception as e:
      pass

pass
def get_icon_path():
  '''Get icon path'''
  if getattr(sys,'_MEIPASS',None):
    path = Path(sys._MEIPASS)/'assets'/'Bootstrapper.ico'
    if path.exists():
      return str(path)

  else:
    paths = [Path(sys.executable).parent/'assets'/'Bootstrapper.ico',Path(__file__).parent/'assets'/'Bootstrapper.ico']
    for p in paths:
      if p.exists():
        str(p)
        return

    return None

def monitor_process_integrity(process,client_executable_path,auth_ticket,place_id,session_cookie):
  '''Anti-cheat with FFlag control'''
  try:
    pid = process.pid
    client_process = psutil.Process(pid)
    initial_modules = {}
    fflags = fetch_fflags()
    ac_enabled = fflags.get('FFlagEnableACVoiceChat',True)
    if ac_enabled:
      info('Anti-cheat disabled by FFlag')
      return None
    else:
      silent_mode = fflags.get('FFlagEnableffdFeatSilentMode',False)
      crash_on_detect = fflags.get('FFlagEnableClientSocket',True)
      instant_check = fflags.get('FFlagEnableInstantACCheck',True)
      deep_scan_interval = fflags.get('FIntACDeepScanInterval',8)
      check_interval = fflags.get('FIntACCheckInterval',2)
      if sys.platform != 'win32':
        return None
      else:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        process_handle = kernel32.OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,False,pid)
        if process_handle:
          error('Failed to get process handle for anti-cheat')
          return None
        else:
          if instant_check:
            time.sleep(0.5)
            suspicious_modules = perform_integrity_check(process_handle,client_process,initial_modules,client_executable_path,pid)
            if :
              terminate_with_prejudice(process,client_process,pid)
              send_anticheat_ban_report(auth_ticket,place_id,session_cookie,suspicious_modules)
              return None

          else:
            game_directory = Path(client_executable_path).parent
            try:
              for module in client_process.memory_maps():
                module_path = module.path
                module_name = Path(module_path).name.lower()
                is_in_game_dir = Path(module_path).parent == game_directory
                if is_in_game_dir:
                  if module_name.endswith('.dll'):
                    cert = get_certificate_thumbprint(module_path) if HAS_SIGNIFY else None
                    file_hash = get_file_sha256(module_path)
                    if cert and cert in TRUSTED_CERTIFICATES:
                      initial_modules[module_path.lower()] = (module_name,cert,file_hash)
                      continue

                    if module_name in TRUSTED_FILE_HASHES:
                      if file_hash in TRUSTED_FILE_HASHES[module_name]:
                        initial_modules[module_path.lower()] = (module_name,'hash_verified',file_hash)
                        continue

                      continue

                    continue

                  initial_modules[module_path.lower()] = (module_name,'game_exe',None)
                  continue

                if is_module_trusted(module_path,module_name):
                  continue

                initial_modules[module_path.lower()] = (module_name,'trusted_system',None)
                continue
                (suspicious_modules and crash_on_detect)

            except Exception as e:
              error(f'''Failed to enumerate initial modules: {e}''')

            check_count = 0
            violation_detected = False
            last_deep_scan = time.time()
            if process.poll() is None:
              try:
                suspicious_modules = []
                direct_injections = detect_direct_dll_injection(process_handle,client_process,initial_modules,game_directory)
                if direct_injections:
                  suspicious_modules.extend(direct_injections)

                if time.time()-last_deep_scan > deep_scan_interval:
                  blacklisted = check_process_blacklist()
                  if blacklisted:
                    suspicious_modules.extend(blacklisted)

                  memory_violations = enhanced_memory_scan(process_handle,pid)
                  if memory_violations:
                    suspicious_modules.extend(memory_violations)

                  last_deep_scan = time.time()

                if suspicious_modules:
                  threading.Thread(target=send_anticheat_ban_report,args=(auth_ticket,place_id,session_cookie,suspicious_modules),daemon=True).start()
                  time.sleep(2)
                  if crash_on_detect:
                    violation_detected = True
                    terminate_with_prejudice(process,client_process,pid)

                else:
                  check_count += 1
                  time.sleep(check_interval+check_count%3)
                  if process.poll() is None:
                    while __CHAOS_PY_TEST_NOT_INIT_ERR__:
                      if process_handle:
                        kernel32.CloseHandle(process_handle)
                        return None
                      else:
                        return None

              except Exception as e:
                continue
                if silent_mode:
                  error(f'''Anti-cheat check error: {e}''')

                e = None
                del(e)
                e = None
                del(e)

  except Exception as e:
    error(f'''Anti-cheat monitoring failed: {e}''')
    return None

def monitor_process(process,place_id=None,auth_ticket=None,session_cookie=None):
  '''Monitor process and send periodic heartbeats'''
  try:
    last_heartbeat = time.time()
    while process.poll() is None:
      if __CHAOS_PY_NULL_PTR_VALUE_ERR__ > time.time()-last_heartbeat:
        try:
          if heartbeat_success:
            pass

          time.sleep(5)
        except Exception as e:
          e = None
          del(e)
          e = None
          del(e)

  except:
    (auth_ticket and place_id and 45)
    close_discord_rpc()

  close_discord_rpc()

def http_get(url,max_retries=3):
  for attempt in range(max_retries):
    try:
      response = requests.get(url,timeout=10)
      response.raise_for_status()
    except Exception as e:
      if attempt < max_retries-1:
        time.sleep(1)

      raise

    response.text
    return

def download_file(url,path,max_retries=5):
  for attempt in range(max_retries):
    if cancel_flag.is_set():
      return False
    else:
      try:
        response = requests.get(url,stream=True,timeout=30)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length',0))
        if total_size == 0:
          if attempt < max_retries-1:
            time.sleep(2)
            continue

          error('Server did not provide content length')
          return False
        else:
          update_status('Downloading... 0%')
          downloaded = 0
          last_update = time.time()
          with open(path,'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
              if cancel_flag.is_set():
                None(None,None)
                return False
              else:
                if chunk:
                  continue

                f.write(chunk)
                downloaded += len(chunk)
                now = time.time()
                if now-last_update >= 0.1:
                  continue

                if total_size > 0:
                  progress = int(downloaded/total_size*100)
                  update_status(f'''Downloading... {progress}%''')

                last_update = now
                continue
                update_status('Download complete')
                return True

      except (requests.exceptions.RequestException,IOError) as e:
        if attempt < max_retries-1:
          error(f'''Download failed (attempt {attempt+1}/{max_retries}), retrying...''')
          update_status(f'''Download failed, retrying... ({attempt+1}/{max_retries})''')
          time.sleep(2**attempt)

        error(f'''Download failed after {max_retries} attempts: {e}''')
        update_status('Download failed. Please check your connection and try again.')
        return False

  return False

def download_file_prefix(url,path_prefix):
  url_hash = hashlib.md5(url.encode()).hexdigest()
  path = path_prefix/url_hash
  if path.exists():
    try:
      with zipfile.ZipFile(path,'r') as test_zip:
        test_zip.testzip()

    except (zipfile.BadZipFile,Exception):
      info('Cached file corrupted, re-downloading...')
      try:
        path.unlink()
      except:
        pass

    info(f'''Using cached file: {path.name}''')
    return path
  else:
    success = download_file(url,path)
    if success:
      if path.exists():
        try:
          path.unlink()
          return None
        except:
          return None

      else:
        return None

    else:
      try:
        with zipfile.ZipFile(path,'r') as test_zip:
          test_zip.testzip()

      except (zipfile.BadZipFile,Exception):
        error('Downloaded file is corrupted, retrying...')
        try:
          path.unlink()
        except:
          pass

      except:
        success = download_file(url,path)
        if success:
          return None
        else:
          return path

      return path

def create_folder_if_not_exists(path):
  if path.exists():
    info(f'''Creating folder {path}''')
    path.mkdir(parents=True,exist_ok=True)
    return None
  else:
    return None

def get_sha1_hash_of_file(path):
  hasher = hashlib.sha1()
  try:
    with open(path,'rb') as f:
      while (chunk := f.read(8192)):
        hasher.update(chunk)

      return hasher.hexdigest()

  except OSError as e:
    if e.errno == 22:
      try:
        normalized_path = str(path).replace('\\\\','\\')
        with open(normalized_path,'rb') as f:
          while (chunk := f.read(8192)):
            hasher.update(chunk)

      except:
        pass

      return __CHAOS_PY_NULL_PTR_VALUE_ERR__.hexdigest()

    error(f'''Failed to hash file: {e}''')
    return hashlib.sha1(str(time.time()).encode()).hexdigest()
  except Exception as e:
    error(f'''Failed to hash file: {e}''')
    return hashlib.sha1(str(time.time()).encode()).hexdigest()
  except:
    pass

def get_installation_directory():
  if sys.platform == 'darwin':
    return Path.home()/'Library'/'Application Support'/'Syntax'
  else:
    if sys.platform == 'win32':
      return Path(os.getenv('LOCALAPPDATA'))/'Syntax'
    else:
      return Path.home()/'.local'/'share'/'Syntax'

def extract_place_id(url):
  if 'placeId=' in url:
    start = url.find('placeId=')+8
    end = url.find('&',start)
    if end == -1:
      return url[start:]
    else:
      return url[start:end]

  else:
    return None

def clear_screen():
  if sys.platform == 'win32':
    os.system('cls')
    return None
  else:
    os.system('clear')
    return None

def load_hash_cache(installation_dir):
  cache_path = installation_dir/'LauncherSettings.json'
  if cache_path.exists():
    try:
      with open(cache_path,'r') as f:
        return json.load(f)
        return {'clients':{}}

    except:
      return {'clients':{}}

def save_hash_cache(installation_dir,cache):
  cache_path = installation_dir/'LauncherSettings.json'
  try:
    with open(cache_path,'w') as f:
      json.dump(cache,f,indent=2)

  except:
    return None

def fetch_fflags(http_client=None):
  fflag_url = 'https://clientsettingscdn.synt2x.xyz/v1/settings/application?applicationName=PCClientBootstrapper'
  try:
    response = http_get(fflag_url)
    data = json.loads(response)
    if 'applicationSettings' in data:
      return data['applicationSettings']
    else:
      pass
      return {}

  except:
    return {}

def fetch_user_channel(place_id=None):
  '''
Fetch the user channel from the v2 endpoint
Sends place_id in headers if available
'''
  channel_url = 'https://clientsettingscdn.synt2x.xyz/v2/user-channel'
  try:
    headers = {}
    if place_id:
      headers['Roblox-Place-Id'] = str(place_id)

    response = requests.get(channel_url,headers=headers,timeout=10)
    response.raise_for_status()
    data = response.json()
    if 'channelName' in data:
      return data['channelName']
    else:
      pass
      return None

  except Exception as e:
    error(f'''Failed to fetch user channel: {e}''')
    return None

def should_add_channel_param(client_year,channel):
  '''
1. Client year must be 2020 or above
2. Channel must not be "LIVE"
'''
  if channel:
    if channel == 'LIVE':
      return False
    else:
      try:
        year = int(client_year)
        return year >= 2020
      except (ValueError,TypeError):
        return False

def extract_zipfile_long_paths(zip_path,extract_to):
  extract_to = str(Path(extract_to).resolve())
  with zipfile.ZipFile(zip_path,'r') as zip_ref:
    members = zip_ref.namelist()
    total_files = len(members)
    for idx,member in enumerate(members):
      if cancel_flag.is_set():
        None(None,None)
        return False
      else:
        if idx%10 == 0:
          progress = int(idx/total_files*100)
          update_status(f'''Extracting... {progress}%''')

        member_normalized = member_normalized if sys.platform == 'win32' else member.replace('/','\\')
        target_path = os.path.join(extract_to,member_normalized)
        if sys.platform == 'win32' and target_path.startswith('\\\\?\\'):
          target_path = f'''\\\\?\\{target_path}'''

        if member.endswith('/'):
          os.makedirs(target_path,exist_ok=True)
          continue

        dir_path = os.path.dirname(target_path)
        os.makedirs(dir_path,exist_ok=True)
        with zip_ref.open(member) as source:
          with open(target_path,'wb') as target:
            shutil.copyfileobj(source,target)

  update_status('Extraction complete')
  return True

def check_and_update_clients(current_version_directory,temp_downloads_directory,installation_directory):
  if sys.platform == 'darwin':
    platform = 'mac'
  else:
    platform = platform if sys.platform == 'linux' else 'linux'

  api_url = f'''https://clientsettingscdn.synt2x.xyz/v1/client-versions?platform={platform}'''
  cache = load_hash_cache(installation_directory)
  try:
    response = http_get(api_url)
    data = json.loads(response)
    if 'clients' in data:
      for year,client_info in data['clients'].items():
        if cancel_flag.is_set():
          raise Exception('Installation cancelled by user')

        if 'url' not in client_info or 'hash' not in client_info:
          continue

        download_url = client_info['url']
        expected_hash = client_info['hash']
        client_dir = current_version_directory/f'''Client{year}'''
        exe_path = client_dir/exe_path if sys.platform == 'darwin' else client_dir/'RobloxPlayer.app'/'Contents'/'MacOS'/'RobloxPlayer'
        cached_hash = cache['clients'].get(year)
        if not(exe_path.exists()):
          pass

        needs_update = cached_hash != expected_hash
        if needs_update:
          continue

        update_status(f'''Updating client {year}...''')
        if client_dir.exists():
          update_status(f'''Removing old client {year}...''')
          force_remove_directory(client_dir)

        create_folder_if_not_exists(client_dir)
        try:
          zip_path = download_file_prefix(download_url,temp_downloads_directory)
          if zip_path:
            raise Exception(f'''Failed to download client {year}''')

          update_status(f'''Preparing to extract client {year}...''')
          time.sleep(0.5)
          update_status(f'''Extracting client {year}...''')
          success = extract_zipfile_long_paths(zip_path,client_dir)
          if success:
            raise Exception('Extraction cancelled')

        except Exception as e:
          error(f'''Failed to install client {year}: {e}''')
          update_status(f'''Failed to install client {year}. Please try again.''')
          if client_dir.exists():
            force_remove_directory(client_dir)

          raise

        try:
          zip_path.unlink()
          cache['clients'][year] = expected_hash
          continue
          save_hash_cache(installation_directory,cache)
          return None
        except:
          pass

  except Exception as e:
    error(f'''Client update failed: {e}''')
    raise

def download_specific_client(client_year,current_version_directory,temp_downloads_directory,installation_directory):
  if sys.platform == 'darwin':
    platform = 'mac'
  else:
    platform = platform if sys.platform == 'linux' else 'linux'

  api_url = f'''https://clientsettingscdn.synt2x.xyz/v1/client-versions?platform={platform}'''
  cache = load_hash_cache(installation_directory)
  try:
    response = http_get(api_url)
    data = json.loads(response)
    if 'clients' in data and client_year in data['clients']:
      client_info = data['clients'][client_year]
      if 'url' in client_info:
        download_url = client_info['url']
        client_dir = current_version_directory/f'''Client{client_year}'''
        exe_path = client_dir/exe_path if sys.platform == 'darwin' else client_dir/'RobloxPlayer.app'/'Contents'/'MacOS'/'RobloxPlayer'
        cached_hash = cache['clients'].get(client_year)
        expected_hash = client_info.get('hash')
        if (not(exe_path.exists()) or expected_hash):
          pass

        needs_update = cached_hash != expected_hash
        if needs_update:
          update_status(f'''Downloading client {client_year}...''')
          if client_dir.exists():
            update_status(f'''Removing old client {client_year}...''')
            force_remove_directory(client_dir)

          create_folder_if_not_exists(client_dir)
          zip_path = download_file_prefix(download_url,temp_downloads_directory)
          if zip_path:
            return False
          else:
            update_status(f'''Extracting client {client_year}...''')
            success = extract_zipfile_long_paths(zip_path,client_dir)
            if success:
              return False
            else:
              try:
                zip_path.unlink()
                if expected_hash:
                  cache['clients'][client_year] = expected_hash
                  save_hash_cache(installation_directory,cache)

                return True
                if expected_hash:
                  cache['clients'][client_year] = expected_hash
                  save_hash_cache(installation_directory,cache)

              except:
                pass

  except:
    return False

def register_session_with_retry(auth_ticket,place_id,machine_id,max_retries=3):
  '''Register session with server time synchronization'''
  for attempt in range(max_retries):
    try:
      server_time_response = requests.get('https://apis.synt2x.xyz/v1/server-time',timeout=5)
      if server_time_response.status_code == 200:
        server_data = server_time_response.json()
        timestamp = int(server_data.get('timestamp',time.time()))
      else:
        timestamp = int(time.time())

      signature = generate_secure_token(auth_ticket,str(place_id),machine_id,timestamp)
      response = requests.post('https://apis.synt2x.xyz/v1/register-session',json={'authTicket':auth_ticket,'placeId':str(place_id),'timestamp':timestamp,'machineId':machine_id,'signature':signature},timeout=5)
      if response.status_code == 200:
        return True
      else:
        if response.status_code == 403 and attempt < max_retries-1:
          info(f'''Session registration failed (attempt {attempt+1}), retrying...''')
          time.sleep(1)
          continue

        error(f'''Session registration failed: {response.status_code}''')
        return False

    except Exception as e:
      if attempt < max_retries-1:
        time.sleep(1)

      error(f'''Session registration error: {e}''')
      return False

  return False

def send_heartbeat(auth_ticket,place_id,session_cookie,process_pid):
  '''Send periodic heartbeat to prove launcher is still monitoring'''
  try:
    payload = {'authTicket':auth_ticket,'placeId':place_id,'sessionCookie':session_cookie,'processPid':process_pid,'machineId':get_machine_id(),'timestamp':int(time.time())}
    response = requests.post('https://apis.synt2x.xyz/v1/launcher-heartbeat',json=payload,headers={'Content-Type':'application/json'},timeout=5)
    return response.status_code == 200
  except:
    return False

def cancel_launch():
  info('Launch cancelled by user')
  cancel_flag.set()
  if status_window:
    try:
      status_window['root'].destroy()
    except:
      pass

  close_discord_rpc()
  release_mutex()
  sys.exit(0)

def create_status_window(fflags):
  global status_window
  try:
    import tkinter as tk
    from tkinter import ttk
    from PIL import Image, ImageTk
    root = tk.Tk()
    root.title('SYNTAX 2')
    root.geometry('500x230')
    root.resizable(False,False)
    if sys.platform == 'win32':
      try:
        import ctypes
        myappid = 'synt2x.launcher.1.0'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
      except:
        pass

  except Exception as e:
    error(f'''Failed to create status window: {e}''')
    return None

  try:
    icon_path = None
    if getattr(sys,'_MEIPASS',None):
      icon_path = Path(sys._MEIPASS)/'assets'/'Bootstrapper.ico'
    else:
      icon_path = Path(sys.executable).parent/'assets'/'Bootstrapper.ico'
      if icon_path.exists():
        icon_path = Path(__file__).parent/'assets'/'Bootstrapper.ico'

    if icon_path and icon_path.exists():
      root.iconbitmap(str(icon_path))

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = screen_width-500//2
    y = screen_height-230//2
    root.geometry(f'''500x230+{x}+{y}''')
    root.configure(bg='#ffffff')
    root.overrideredirect(True)
    if sys.platform == 'win32':
      try:
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        if hwnd == 0:
          root.update()
          hwnd = ctypes.windll.user32.FindWindowW(None,'SYNTAX 2')

        GWL_EXSTYLE = -20
        WS_EX_APPWINDOW = 262144
        WS_EX_TOOLWINDOW = 128
        style = ctypes.windll.user32.GetWindowLongW(hwnd,GWL_EXSTYLE)
        style = style&~(WS_EX_TOOLWINDOW)
        style = style|WS_EX_APPWINDOW
        ctypes.windll.user32.SetWindowLongW(hwnd,GWL_EXSTYLE,style)
        SWP_FRAMECHANGED = 32
        SWP_NOMOVE = 2
        SWP_NOSIZE = 1
        SWP_NOZORDER = 4
        ctypes.windll.user32.SetWindowPos(hwnd,0,0,0,0,0,SWP_FRAMECHANGED|SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER)
        main_frame = tk.Frame(root,bg='#ffffff',highlightthickness=1,highlightbackground='#e0e0e0')
        main_frame.pack(fill='both',expand=True)
        content_frame = tk.Frame(main_frame,bg='#ffffff')
        content_frame.pack(expand=True,fill='both',padx=40,pady=30)
        icon_loaded = False
      except:
        pass

  except:
    pass

  try:
    icon_path = None
    if getattr(sys,'_MEIPASS',None):
      icon_path = Path(sys._MEIPASS)/'assets'/'Bootstrapper.ico'
    else:
      icon_path = Path(sys.executable).parent/'assets'/'Bootstrapper.ico'
      if icon_path.exists():
        icon_path = Path(__file__).parent/'assets'/'Bootstrapper.ico'

    if :
      icon_label.pack(pady=(10,15))

    if icon_loaded:
      icon_label = icon_label if fflags.get('FFlagUseAlternateBootstrapperIcon',False) else tk.Label(content_frame,text='◈',font=('Segoe UI',48),bg='#ffffff',fg='#000000')
      icon_label.pack(pady=(10,15))

    status_label = tk.Label(content_frame,text='Initializing...',font=('Segoe UI',11),bg='#ffffff',fg='#000000')
    status_label.pack(pady=(0,20))
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('Custom.Horizontal.TProgressbar',troughcolor='#e0e0e0',background='#0078d7',borderwidth=0,thickness=4)
    progress = ttk.Progressbar(content_frame,mode='indeterminate',length=380,style='Custom.Horizontal.TProgressbar')
    progress.pack(pady=(0,15))
    progress.start(8)
    cancel_button = tk.Button(content_frame,text='Cancel',command=lambda : cancel_launch(),font=('Segoe UI',9),bg='#f0f0f0',fg='#000000',relief='flat',borderwidth=1,padx=30,pady=8,cursor='hand2')
    cancel_button.pack(pady=(5,0))
    def on_enter(e):
      cancel_button['bg'] = '#e5e5e5'

    def on_leave(e):
      cancel_button['bg'] = '#f0f0f0'

    cancel_button.bind('<Enter>',on_enter)
    cancel_button.bind('<Leave>',on_leave)
    root.attributes('-topmost',True)
    root.update()
    root.attributes('-topmost',False)
    root.lift()
    root.focus_force()
    status_window = {'root':root,'status_label':status_label,'progress':progress,'cancel_button':cancel_button}
    return status_window
  except:
    pass

def create_authentic_roblox_ui(fflags):
  '''Modern Roblox bootstrapper UI - 2024 style'''
  global status_window
  try:
    import tkinter as tk
    from PIL import Image, ImageTk
    root = tk.Tk()
    root.title('Syntax')
    root.geometry('400x300')
    root.resizable(False,False)
    bg_color = '#393B3D'
    root.configure(bg=bg_color)
    root.overrideredirect(True)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = screen_width-400//2
    y = screen_height-300//2
    root.geometry(f'''400x300+{x}+{y}''')
  except Exception as e:
    error(f'''Failed to create UI: {e}''')
    return None

  try:
    icon_path = get_icon_path()
    if icon_path:
      root.iconbitmap(icon_path)

    main_frame = tk.Frame(root,bg=bg_color)
    main_frame.pack(fill='both',expand=True)
    logo_frame = tk.Frame(main_frame,bg=bg_color)
    logo_frame.pack(expand=True,pady=(50,20))
  except:
    pass

  try:
    icon_path = get_icon_path()
    if icon_path:
      logo_img = Image.open(icon_path)
      logo_img = logo_img.resize((100,100),Image.Resampling.LANCZOS)
      logo_photo = ImageTk.PhotoImage(logo_img)
      logo_label = tk.Label(logo_frame,image=logo_photo,bg=bg_color)
      logo_label.image = logo_photo
      logo_label.pack()

    status_label = tk.Label(main_frame,text='Starting Syntax...',font=('Segoe UI',11),bg=bg_color,fg='#FFFFFF')
    status_label.pack(pady=(0,30))
    progress_frame = tk.Frame(main_frame,bg=bg_color)
    progress_frame.pack(pady=(0,35))
    progress_canvas = tk.Canvas(progress_frame,width=350,height=8,bg=bg_color,highlightthickness=0)
    progress_canvas.pack()
    progress_canvas.create_rectangle(0,0,350,8,fill='#2B2D2F',outline='')
    progress_bar = progress_canvas.create_rectangle(0,0,0,8,fill='#00A86B',outline='')
    progress_value = [0]
    animation_running = [True]
    def animate_progress():
      if animation_running[0]:
        return None
      else:
        progress_value[0] = progress_value[0]+3%350
        try:
          bar_width = 100
          x1 = progress_value[0]
          x2 = min(x1+bar_width,350)
          if x2 <= 350:
            progress_canvas.coords(progress_bar,x1,0,x2,8)
          else:
            progress_canvas.coords(progress_bar,0,0,x2-350,8)

          root.after(20,animate_progress)
          return None
        except:
          animation_running[0] = False

        return None

    cancel_button = tk.Button(main_frame,text='Cancel',command=lambda : cancel_launch(),font=('Segoe UI',10),bg='#4A4C4E',fg='#FFFFFF',relief='flat',borderwidth=0,padx=30,pady=8,cursor='hand2')
    cancel_button.pack()
    def on_enter(e):
      cancel_button['bg'] = '#5A5C5E'

    def on_leave(e):
      cancel_button['bg'] = '#4A4C4E'

    cancel_button.bind('<Enter>',on_enter)
    cancel_button.bind('<Leave>',on_leave)
    root.update_idletasks()
    root.deiconify()
    animate_progress()
    status_window = {'root':root,'status_label':status_label,'progress_canvas':progress_canvas,'progress_bar':progress_bar,'animation_running':animation_running}
    return status_window
  except:
    logo_label = tk.Label(logo_frame,text='◆',font=('Segoe UI',60,'bold'),bg=bg_color,fg='#FFFFFF')
    logo_label.pack()

def main():
  global status_window
  if len(sys.argv) > 1 and sys.argv[1] == '--uninstall':
    try:
      import tkinter as tk
      from tkinter import messagebox
      root = tk.Tk()
      root.withdraw()
      result = messagebox.askyesno('Uninstall Syntax 2 Player','''Are you sure you want to uninstall Syntax 2 Player?

This will remove all the files.''')
      if result:
        installation_directory = get_installation_directory()
        if installation_directory.exists():
          info(f'''Removing {installation_directory}''')
          shutil.rmtree(installation_directory,ignore_errors=True)

        import winreg
        try:
          winreg.DeleteKey(winreg.HKEY_CURRENT_USER,'Software\\Classes\\synt2x-player\\shell\\open\\command')
          winreg.DeleteKey(winreg.HKEY_CURRENT_USER,'Software\\Classes\\synt2x-player\\shell\\open')
          winreg.DeleteKey(winreg.HKEY_CURRENT_USER,'Software\\Classes\\synt2x-player\\shell')
          winreg.DeleteKey(winreg.HKEY_CURRENT_USER,'Software\\Classes\\synt2x-player\\DefaultIcon')
          winreg.DeleteKey(winreg.HKEY_CURRENT_USER,'Software\\Classes\\synt2x-player')
          winreg.DeleteKey(winreg.HKEY_CURRENT_USER,'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Syntax2Player')
          start_menu = Path(os.getenv('APPDATA'))/'Microsoft'/'Windows'/'Start Menu'/'Programs'/'Syntax'
          if start_menu.exists():
            shutil.rmtree(start_menu,ignore_errors=True)

          desktop_shortcut = Path(os.path.expanduser('~/Desktop'))/'Syntax 2 Player.lnk'
          if desktop_shortcut.exists():
            desktop_shortcut.unlink()

          messagebox.showinfo('Uninstall Complete','Syntax 2 Player has been uninstalled successfully.')
          root.destroy()
        except:
          pass

    except Exception as e:
      error(f'''Uninstall failed: {e}''')

    sys.exit(0)

  if acquire_mutex():
    error('Another instance of SYNTAX 2 Launcher is already running.')
    try:
      import tkinter as tk
      from tkinter import messagebox
      root = tk.Tk()
      root.withdraw()
      messagebox.showerror('SYNTAX 2 Launcher','''Another instance of the launcher is already running.

Please close the other instance before starting a new one.''')
      root.destroy()
    except:
      download_specific_client(client_year,current_version_directory,temp_downloads_directory,installation_directory)
      print('Another instance is already running. Please close it first.')
      time.sleep(5)

    sys.exit(1)

  clear_screen()
  base_url = 'synt2x.xyz'
  setup_url = 'setup.synt2x.xyz'
  fallback_setup_url = 'dhr7f4aayiel.cloudfront.net'
  if sys.platform == 'darwin':
    bootstrapper_filename = 'SyntaxPlayerMacLauncher'
  else:
    bootstrapper_filename = bootstrapper_filename if sys.platform == 'linux' else 'SyntaxPlayerLinuxLauncher'

  startup_text = f'''
    .d8888b. Y88b   d88P  888b    888 88888888888     d8888 Y88b   d88P 
    d88P  Y88b Y88b d88P  8888b   888     888        d88888  Y88b d88P  
    Y88b.       Y88o88P   88888b  888     888       d88P888   Y88o88P   
     "Y888b.     Y888P    888Y88b 888     888      d88P 888    Y888P    
        "Y88b.    888     888 Y88b888     888     d88P  888    d888b    
          "888    888     888  Y88888     888    d88P   888   d88888b   
    Y88b  d88P    888     888   Y8888     888   d8888888888  d88P Y88b  
    "Y8888P"      888     888    Y888     888  d88P     888 d88P   Y88b
     
   {base_url} | Build Date: {BUILD_DATE} | Version: {VERSION}\n    '''
  terminal_width = shutil.get_terminal_size().columns
  if terminal_width < 80:
    if HAS_COLOR:
      print(f'''{Fore.MAGENTA}{Style.BRIGHT}SYNTAX 2 Bootstrapper | {base_url} | Build Date: {BUILD_DATE} | Version: {VERSION}{Style.RESET_ALL}\n''')
    else:
      print(f'''SYNTAX 2 Bootstrapper | {base_url} | Build Date: {BUILD_DATE} | Version: {VERSION}\n''')

  else:
    lines = startup_text.strip().split('\n')
    for line in lines[:-1]:
      spaces = terminal_width-len(line)//2
      if HAS_COLOR:
        print(f'''{' '*spaces}{Fore.MAGENTA}{Style.BRIGHT}{line}{Style.RESET_ALL}''')
        continue

      print(f'''{' '*spaces}{line}''')

    last_line = lines[-1]
    spaces = terminal_width-len(last_line)//2
    if HAS_COLOR:
      print(f'''{' '*spaces}{Fore.CYAN}{Style.BRIGHT}{last_line}{Style.RESET_ALL}\n''')
    else:
      print(f'''{' '*spaces}{last_line}\n''')

  info('Fetching latest client version from setup server')
  fflags = fetch_fflags()
  try:
    latest_client_version = http_get(f'''https://{setup_url}/version''')
  except Exception as e2:
    error(f'''Failed to fetch latest client version from setup server, attempting to fallback to {fallback_setup_url}''')
    try:
      latest_client_version = http_get(f'''https://{fallback_setup_url}/version''')
      info('Successfully fetched latest client version from fallback setup server')
      setup_url = fallback_setup_url
    except:
      pass

    error('Failed to fetch latest client version from fallback setup server, are you connected to the internet?')
    release_mutex()
    time.sleep(10)
    sys.exit(1)

  info(f'''Latest Client Version: {latest_client_version}''')
  installation_directory = get_installation_directory()
  create_folder_if_not_exists(installation_directory)
  versions_directory = installation_directory/'Versions'
  create_folder_if_not_exists(versions_directory)
  temp_downloads_directory = installation_directory/'Downloads'
  create_folder_if_not_exists(temp_downloads_directory)
  current_version_directory = versions_directory/latest_client_version
  create_folder_if_not_exists(current_version_directory)
  latest_bootstrapper_path = current_version_directory/bootstrapper_filename
  if getattr(sys,'frozen',False):
    current_exe_path = Path(sys.executable)
  else:
    current_exe_path = Path(__file__)

  if str(current_exe_path).startswith(str(current_version_directory)):
    if latest_bootstrapper_path.exists():
      info('Downloading the latest bootstrapper')
      success = download_file(f'''https://{setup_url}/{latest_client_version}-{bootstrapper_filename}''',latest_bootstrapper_path)
      if success:
        error('Failed to download bootstrapper')
        release_mutex()
        time.sleep(10)
        sys.exit(1)

    latest_bootstrapper_hash = get_sha1_hash_of_file(latest_bootstrapper_path)
    current_exe_hash = get_sha1_hash_of_file(current_exe_path)
    if latest_bootstrapper_hash != current_exe_hash:
      info('Starting latest bootstrapper')
      if sys.platform == 'win32':
        try:
          release_mutex()
          subprocess.Popen([str(latest_bootstrapper_path)]+sys.argv[1:])
        except Exception:
          info('Found bootstrapper was corrupted! Downloading...')
          latest_bootstrapper_path.unlink()
          download_file(f'''https://{setup_url}/{latest_client_version}-{bootstrapper_filename}''',latest_bootstrapper_path)
          subprocess.Popen([str(latest_bootstrapper_path)]+sys.argv[1:])

      else:
        if sys.platform == 'darwin':
          os.chmod(latest_bootstrapper_path,493)
          release_mutex()
        else:
          os.chmod(latest_bootstrapper_path,493)
          try:
            for root_dir,dirs,files in os.walk(current_version_directory):
              for file in files:
                file_path = Path(root_dir)/file
                if file_path.suffix in ('.exe','') and 'client' in file.lower():
                  continue

                try:
                  os.chmod(file_path,493)
                  continue
                  continue
                except:
                  continue

          except Exception as e:
            pass

          try:
            applications_dir = Path.home()/'.local'/'share'/'applications'
            applications_dir.mkdir(parents=True,exist_ok=True)
            desktop_file_content = f'''[Desktop Entry]
                    Name=Syntax Launcher
                    Exec={latest_bootstrapper_path} %u\n                    Icon={latest_bootstrapper_path}
                    Type=Application
                    Terminal=false
                    Categories=Game;
                    Version={VERSION}
                    MimeType=x-scheme-handler/synt2x-player;
                    StartupNotify=true
                    '''
            desktop_file_path = applications_dir/'synt2x-player.desktop'
            desktop_file_path.write_text(desktop_file_content)
            os.chmod(desktop_file_path,493)
          except Exception as e:
            pass

          try:
            subprocess.run(['xdg-mime','default','synt2x-player.desktop','x-scheme-handler/synt2x-player'],capture_output=True,timeout=5,check=False)
          except:
            pass

          try:
            subprocess.run(['update-desktop-database',str(applications_dir)],capture_output=True,timeout=5,check=False)
            info('✓ Protocol handler registered')
          except:
            pass

          info('Please launch SYNTAX 2 from the website, to continue with the update process.')
          release_mutex()
          time.sleep(20)

      sys.exit(0)

  app_settings_path = current_version_directory/'AppSettings.xml'
  is_fresh_install = not(app_settings_path.exists())
  needs_shortcut_update = should_update_shortcuts(installation_directory,latest_bootstrapper_path)
  if is_fresh_install:
    update_status('Downloading client files...')
    for item in current_version_directory.iterdir():
      if item.is_file() and item != latest_bootstrapper_path:
        try:
          item.unlink()
        except:
          continue

        continue

      if item.is_dir():
        try:
          shutil.rmtree(item)
        except:
          continue

        continue
        (fflags.get('FFlagEnableBootstrapperUI',True) and create_status_window(fflags))

    create_folder_if_not_exists(temp_downloads_directory)
    try:
      check_and_update_clients(current_version_directory,temp_downloads_directory,installation_directory)
    except Exception as e:
      if cancel_flag.is_set():
        info('Installation cancelled')
      else:
        error(f'''Installation failed: {e}''')

      if status_window:
        try:
          status_window['root'].destroy()
        except:
          pass

      close_discord_rpc()
      release_mutex()
      sys.exit(1)

    update_status('Cleaning up...')
    if temp_downloads_directory.exists():
      try:
        shutil.rmtree(temp_downloads_directory)
      except:
        pass

    update_status('Creating shortcuts...')
    create_shortcuts_with_folder(installation_directory,latest_bootstrapper_path)
    update_status('Registering protocol...')
    register_protocol_handler_windows(latest_bootstrapper_path)
    register_uninstaller(installation_directory,latest_bootstrapper_path)
    update_status('Finalizing...')
    app_settings_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
    <Settings>
        <ContentFolder>content</ContentFolder>
        <BaseUrl>http://{base_url}</BaseUrl>\n    </Settings>'''
    app_settings_path.write_text(app_settings_xml)
    for item in versions_directory.iterdir():
      if item.is_dir():
        continue

      if item != current_version_directory:
        continue

      try:
        shutil.rmtree(item)
      except:
        continue

    update_status('Installation complete!')
    if status_window:
      try:
        status_window['animation_running'][0] = False
        status_window['progress_canvas'].coords(status_window['progress_bar'],0,0,350,8)
        time.sleep(2)
        status_window['root'].destroy()
        status_window = None
      except:
        pass

  else:
    if needs_shortcut_update:
      info('Updating shortcuts to new launcher location...')
      try:
        create_shortcuts_with_folder(installation_directory,latest_bootstrapper_path)
        register_protocol_handler_windows(latest_bootstrapper_path)
        info('✓ Shortcuts updated successfully')
      except Exception as e:
        error(f'''Failed to update shortcuts: {e}''')

  if len(sys.argv) == 1:
    info('Fetching FFlags')
    fflags = fetch_fflags()
    if sys.platform == 'win32':
      games_url = f'''https://synt2x.xyz{fflags.get('FStringGamesUrlPath','/games/?referrer=synt2x-player&unloaded=true')}'''
      os.system(f'''start {games_url}''')
    else:
      os.system('xdg-open https://synt2x.xyz/games')

    release_mutex()
    sys.exit(0)

  main_args = sys.argv[1].replace('synt2x-player://','')
  if '%3A' in main_args or '%2F' in main_args:
    main_args = [unquote(arg) for arg in main_args.split('+')]
  else:
    main_args = main_args.split('+')

  launch_mode = ''
  authentication_ticket = ''
  join_script = ''
  client_year = ''
  universe_id = ''
  browser_tracker_id = ''
  roblox_locale = ''
  game_locale = ''
  launch_exp = ''
  channel = None
  for arg in main_args:
    if ':' in arg:
      continue

    key,value = arg.split(':',1)
    if key == 'launchmode':
      launch_mode = value
      continue

    if key == 'gameinfo':
      authentication_ticket = value
      continue

    if key == 'placelauncherurl':
      join_script = value
      place_id = extract_place_id(join_script)
      if place_id:
        universe_id = place_id
        continue

      continue

    if key == 'clientyear':
      client_year = value
      continue

    if key == 'browsertrackerid':
      browser_tracker_id = value
      continue

    if key == 'robloxLocale':
      roblox_locale = value
      continue

    if key == 'gameLocale':
      game_locale = value
      continue

    if key == 'LaunchExp':
      launch_exp = value
      continue

    if key == 'channel':
      continue

    channel = value
    continue
    (status_window or (fflags.get('FFlagEnableBootstrapperUI',False) and create_status_window(fflags)))

  if (client_year and 'null') and universe_id:
    api_url = f'''https://apis.synt2x.xyz/v1/get-universe-version?universeId={universe_id}'''
    try:
      response = http_get(api_url)
      data = json.loads(response)
      if 'version' in data:
        client_year = data['version']

    except:
      __CHAOS_PY_NO_FUNC_ERR__(universe_id if fetch_user_channel else None)
      client_year = '2016'

  if (client_year and 'null'):
    client_year = '2016'

  custom_wine = 'wine'
  if sys.platform not in ('win32','darwin'):
    wine_path_file = installation_directory/'winepath.txt'
    if wine_path_file.exists():
      custom_wine = wine_path_file.read_text().strip()
      info(f'''Using custom wine binary: {custom_wine}''')
    else:
      info('No custom wine binary specified, using default wine command')
      info(f'''If you want to use a custom wine binary, please create a file at {wine_path_file}''')

  if sys.platform == 'darwin':
    client_executable_path = current_version_directory/'Client2021'/'RobloxPlayer.app'/'Contents'/'MacOS'/'RobloxPlayer'
  else:
    client_map = {'1998':'Client1998','2000':'Client2000','2012':'Client2012','2013':'Client2013','2014':'Client2014','2016':'Client2016','2018':'Client2018','2019':'Client2019','2020':'Client2020','2021':'Client2021','2023':'Client2023','2025':'Client2025','2026':'Client2026'}
    client_folder = client_map.get(client_year,'Client2016')
    client_executable_path = current_version_directory/client_folder/'SyntaxPlayerBeta.exe'

  requested_client_dir = current_version_directory/f'''Client{client_year}'''
  requested_client_exe = requested_client_dir/requested_client_exe if sys.platform == 'darwin' else requested_client_dir/'RobloxPlayer.app'/'Contents'/'MacOS'/'RobloxPlayer'
  if client_year == '2000':
    requested_client_exe = requested_client_dir/'Polytoria Client.exe'

  if (channel or universe_id) == client_year == client_year != client_year and sys.platform == 'darwin' or client_year != '2016':
    update_status(f'''Client {client_year} not found, downloading...''')
    if success:
      info(f'''Client {client_year} not available, falling back to 2016''')

  if client_executable_path.exists():
    try:
      app_settings_path.unlink()
    except:
      pass

    error('Failed to run SyntaxPlayerBeta.exe, is your antivirus removing it? The bootstrapper will attempt to redownload the client on next launch.')
    release_mutex()
    time.sleep(20)
    sys.exit(1)

  session_cookie = None
  if fflags.get('FFlagEnableACVoiceChat',True):
    session_cookie = fetch_placelauncher_cookie(join_script)
    if session_cookie:
      error('Warning: Could not fetch session cookie, anti-cheat may be limited')

  if launch_mode == 'play':
    if authentication_ticket and universe_id and register_session_with_retry(authentication_ticket,universe_id,get_machine_id()):
      error('Failed to register launcher session after retries')

    update_status('Launching SYNTAX 2...')
    if fflags.get('FFlagEnableDiscordRPC',True):
      info('Initializing Discord Rich Presence')
      if init_discord_rpc():
        info('Discord RPC connected')
        if universe_id:
          update_discord_presence(universe_id,'In Game')
        else:
          update_discord_presence(None,'In Game')

      else:
        info('Discord RPC unavailable (pypresence not installed or Discord not running)')

    if sys.platform == 'win32':
      command = [str(client_executable_path)]
      if client_year == '2012':
        command.extend(['-a',f'''http://{base_url}/Login/Negotiate.ashx''','-j',join_script,'-t',authentication_ticket])
      else:
        if client_year in ('2023','2025'):
          tracker_id = browser_tracker_id if browser_tracker_id else '0'
          launch_time = int(time.time()*1000)
          command.extend(['--app','-t',authentication_ticket,'-j',join_script,'-b',tracker_id,f'''--launchtime={launch_time}''','--rloc','en_us','--gloc','en_us'])
        else:
          if client_year == '2000':
            command = [str(client_executable_path.parent/'Polytoria Client.exe')]
            command.extend(['-network','client','-token',authentication_ticket])
          else:
            command.extend(['--play','--authenticationUrl',f'''https://{base_url}/Login/Negotiate.ashx''','--authenticationTicket',authentication_ticket,'--joinScriptUrl',join_script])
            if should_add_channel_param(client_year,channel):
              command.extend(['--channel',channel])

      process = subprocess.Popen(command)
      if status_window:
        for i in range(30):
          try:
            status_window['root'].update()
            time.sleep(0.1)
          except:
            continue

          continue
          (requested_client_exe.exists() or '2016')

        try:
          status_window['root'].destroy()
          status_window = None
        except:
          pass

      monitor_thread = threading.Thread(target=monitor_process,args=(process,universe_id,authentication_ticket,session_cookie))
      monitor_thread.daemon = True
      monitor_thread.start()
      if fflags.get('FFlagEnableACVoiceChat',True):
        monitor_process_integrity(process,client_executable_path,authentication_ticket,universe_id,session_cookie)
      else:
        monitor_thread.join()

    else:
      if sys.platform == 'darwin':
        command = [str(client_executable_path),'-authURL',f'''https://{base_url}/Login/Negotiate.ashx''','-scriptURL',join_script,'-ticket',authentication_ticket]
        process = subprocess.Popen(command)
        if status_window:
          for i in range(30):
            try:
              status_window['root'].update()
              time.sleep(0.1)
            except:
              continue

            continue
            current_version_directory/'Client2016'/'SyntaxPlayerBeta.exe'

          try:
            status_window['root'].destroy()
            status_window = None
          except:
            pass

        monitor_thread = threading.Thread(target=monitor_process,args=(process,universe_id,authentication_ticket,session_cookie))
        monitor_thread.daemon = True
        monitor_thread.start()
        if fflags.get('FFlagEnableACVoiceChat',True):
          monitor_process_integrity(process,client_executable_path,authentication_ticket,universe_id,session_cookie)
        else:
          monitor_thread.join()

      else:
        command = [custom_wine,str(client_executable_path)]
        if client_year == '2012':
          command.extend(['-a',f'''http://{base_url}/Login/Negotiate.ashx''','-j',join_script,'-t',authentication_ticket])
        else:
          if client_year in ('2023','2025'):
            tracker_id = browser_tracker_id if browser_tracker_id else '0'
            launch_time = int(time.time()*1000)
            command.extend(['--app','-t',authentication_ticket,'-j',join_script,'-b',tracker_id,f'''--launchtime={launch_time}''','--rloc','en_us','--gloc','en_us'])
          else:
            if client_year == '2000':
              command = [str(client_executable_path.parent/'Polytoria Client.exe')]
              command.extend(['-network','client','-token',authentication_ticket])
            else:
              command.extend(['--play','--authenticationUrl',f'''https://{base_url}/Login/Negotiate.ashx''','--authenticationTicket',authentication_ticket,'--joinScriptUrl',join_script])
              if should_add_channel_param(client_year,channel):
                command.extend(['--channel',channel])

        process = subprocess.Popen(command)
        if status_window:
          for i in range(30):
            try:
              status_window['root'].update()
              time.sleep(0.1)
            except:
              continue

            continue
            while __CHAOS_PY_TEST_NOT_INIT_ERR__:
              try:
                status_window['root'].destroy()
                status_window = None
              except:
                pass

              monitor_thread = threading.Thread(target=monitor_process,args=(process,universe_id,authentication_ticket,session_cookie))
              monitor_thread.daemon = True
              monitor_thread.start()
              if fflags.get('FFlagEnableACVoiceChat',True):
                monitor_process_integrity(process,client_executable_path,authentication_ticket,universe_id,session_cookie)
              else:
                monitor_thread.join()

              release_mutex()
              sys.exit(0)
              return None
              error('Unknown launch mode, exiting.')
              close_discord_rpc()
              release_mutex()
              time.sleep(10)
              sys.exit(1)
              return None

if __name__ == '__main__':
  try:
    main()
  except Exception as e:
    info('Launcher interrupted by user')
    cancel_launch()
    error(f'''Fatal error: {e}''')
    import traceback
    traceback.print_exc()
    release_mutex()
    close_discord_rpc()
    time.sleep(10)
    e = None
    del(e)
    e = None
    del(e)
  finally:
    close_discord_rpc()
    release_mutex()
