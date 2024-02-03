#!/usr/bin/env python3

# This is a utility for looking up the symbol names and/or file+line numbers
# of code addresses. There are several possible sources of this information,
# with varying granularity (listed here in approximate preference order).

# If the wasm has DWARF info, llvm-symbolizer can show the symbol, file, and
# line/column number, potentially including inlining.
# If the wasm has separate DWARF info, do the above with the side file
# If there is a source map, we can parse it to get file and line number.
# If there is an emscripten symbol map, we can parse that to get the symbol name
# If there is a name section or symbol table, llvm-nm can show the symbol name.

import argparse
import json
import os
import numbers
import pickle
import re
import subprocess
import sys
from tools import shared
from tools import webassembly
from tools import wasm_offset_converter

LLVM_SYMBOLIZER = os.path.expanduser(
    shared.build_llvm_tool_path(shared.exe_suffix('llvm-symbolizer')))


class Error(BaseException):
  pass


# Class to treat location info in a uniform way across information sources.
class LocationInfo(object):
  def __init__(self, source=None, line=0, column=0, func=None):
    self.source = source
    self.line = line
    self.column = column
    self.func = func

  def print(self):
    source = self.source if self.source else '??'
    func = self.func if self.func else '??'
    print(f'{func}\n{source}:{self.line}:{self.column}')

  def getAsJson(self):
    source = self.source if self.source else '??'
    func = self.func if self.func else '??'
    return {'source': source, 'func': func, 'line': self.line, 'column':self.column}


def get_codesec_offset(module):
  sec = module.get_section(webassembly.SecType.CODE)
  if not sec:
    raise Error(f'No code section found in {module.filename}')
  return sec.offset


def has_debug_line_section(module):
  for sec in module.sections():
    if sec.name == ".debug_line":
      return True
  return False


def symbolize_address_dwarf(module, address):
  vma_adjust = get_codesec_offset(module)
  cmd = [LLVM_SYMBOLIZER, '-e', module.filename, f'--adjust-vma={vma_adjust}',
         str(address)]
  out = shared.run_process(cmd, stdout=subprocess.PIPE).stdout.strip()
  out_lines = out.splitlines()
  # Source location regex, e.g., /abc/def.c:3:5
  SOURCE_LOC_RE = re.compile(r'(.+):(\d+):(\d+)$')
  # llvm-dwarfdump prints two lines per location. The first line contains a
  # function name, and the second contains a source location like
  # '/abc/def.c:3:5'. If the function or source info is not available, it will
  # be printed as '??', in which case we store None. If the line and column info
  # is not available, they will be printed as 0, which we store as is.
  for i in range(0, len(out_lines), 2):
    func, loc_str = out_lines[i], out_lines[i + 1]
    m = SOURCE_LOC_RE.match(loc_str)
    source, line, column = m.group(1), m.group(2), m.group(3)
    if func == '??':
      func = None
    if source == '??':
      source = None
    LocationInfo(source, line, column, func).print()


def get_sourceMappingURL_section(module):
  for sec in module.sections():
    if sec.name == "sourceMappingURL":
      return sec
  return None


class WasmSourceMap(object):
  class Location(object):
    def __init__(self, source=None, line=0, column=0, func=None):
      self.source = source
      self.line = line
      self.column = column
      self.func = func
    def __repr__(self) -> str:
      return "Location(source={0},line={1},column={2},func={3})".format(
        self.source, self.line, self.column, self.func
      )

  def __init__(self, offsetConverter):
    self.offsetConverter = offsetConverter
    self.version = None
    self.sources = []
    self.mappings = {}
    self.offsets = []
    self.names = {}

  def parse(self, filename):
    with open(filename) as f:
      source_map_json = json.loads(f.read())
      if shared.DEBUG:
        print(source_map_json)

    self.version = source_map_json['version']
    self.sources = source_map_json['sources']
    self.names = source_map_json['names']

    vlq_map = {}
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    for i, c in enumerate(chars):
      vlq_map[c] = i

    def decodeVLQ(string):
      result = []
      shift = 0
      value = 0
      for c in string:
        try:
          integer = vlq_map[c]
        except ValueError:
          raise Error(f'Invalid character ({c}) in VLQ')
        value += (integer & 31) << shift
        if integer & 32:
          shift += 5
        else:
          negate = value & 1
          value >>= 1
          result.append(-value if negate else value)
          value = shift = 0
      return result

    offset = 0
    src = 0
    name = 0
    line = 1
    col = 1
    for segment in source_map_json['mappings'].split(','):
      data = decodeVLQ(segment)
      if shared.DEBUG:
        print("\n data: {} \n".format(data))
      info = []

      offset += data[0]
      if len(data) >= 2:
        src += data[1]
        info.append(src)
      if len(data) >= 3:
        line += data[2]
        info.append(line)
      if len(data) >= 4:
        col += data[3]
        info.append(col)
      # if len(data) >= 5:
      #   print("Name exists!!")
      #   name += data[4]
      #   info.append(name)

      info.append(self.offsetConverter.getName(offset))

      self.mappings[offset] = WasmSourceMap.Location(*info)
      self.offsets.append(offset)
    self.offsets.sort()

  def find_offset(self, offset):
    # Find the largest mapped offset <= the search offset
    lo = 0
    hi = len(self.offsets)

    while lo < hi:
      mid = (lo + hi) // 2
      if self.offsets[mid] > offset:
        hi = mid
      else:
        lo = mid + 1
    if lo >= len(self.offsets):
      print("--->find_offset: offset_len: {0}, ret_lo:{1}".format(len(self.offsets), lo))
    return self.offsets[lo - 1]

  def lookup(self, offset):
    nearest = self.find_offset(offset)
    assert nearest in self.mappings, 'Sourcemap has an offset with no mapping'
    info = self.mappings[nearest]
    offset_converter_ret = self.offsetConverter.getName(offset)
    locInfo = LocationInfo(
        self.sources[info.source] if info.source is not None else None,
        info.line,
        info.column,
        offset_converter_ret
        # info.func
        #self.names[info.func]
      )
    #print(f'offset: {hex(offset)}, nearest: {hex(nearest)}, info: {info}, offsetConvRet: {offset_converter_ret}')
    return locInfo


def symbolize_address_sourcemap(module, address, force_file, offsetConverter):
  URL = force_file
  if not URL:
    # If a sourcemap file is not forced, read it from the wasm module
    section = get_sourceMappingURL_section(module)
    assert section
    module.seek(section.offset)
    assert module.read_string() == 'sourceMappingURL'
    # TODO: support stripping/replacing a prefix from the URL
    URL = module.read_string()

  if shared.DEBUG:
    print(f'Source Mapping URL: {URL}')
  sm = WasmSourceMap(offsetConverter)
  sm.parse(URL)
  if shared.DEBUG:
    csoff = get_codesec_offset(module)
    print(sm.mappings)
    # Print with section offsets to easily compare against dwarf
    for k, v in sm.mappings.items():
      print(f'{k-csoff:x}: {v}')
  sm.lookup(address).print()

def build_address_sourcemap(module, force_file, offsetConverter):
  URL = force_file
  if not URL:
    # If a sourcemap file is not forced, read it from the wasm module
    section = get_sourceMappingURL_section(module)
    assert section
    module.seek(section.offset)
    assert module.read_string() == 'sourceMappingURL'
    # TODO: support stripping/replacing a prefix from the URL
    URL = module.read_string()

  if shared.DEBUG:
    print(f'Source Mapping URL: {URL}')
  sm = WasmSourceMap(offsetConverter)
  sm.parse(URL)
  if shared.DEBUG:
    csoff = get_codesec_offset(module)
    print(sm.mappings)
    # Print with section offsets to easily compare against dwarf
    for k, v in sm.mappings.items():
      print(f'{k-csoff:x}: {v}')
  return sm


def isJSPC(val):
    addr = '{:032b}'.format(val)
    return addr[0] == '1'

def getJSPC(val):
    addr = '{:032b}'.format(val)
    addr = '0' + addr[1:]
    return int(addr, 2)

def get_location_info_from_line(line, pc_addr):
  m = re.search('\(https://(.+?)\)', line)
  file_name = "??"
  line_no = "??"
  col_no = "??"
  function_name = pc_addr
  source_line = None
  if m:
    source_line = m.group(1)
    #print("Found: ", found)
    # Exclude the https substring for function-name.
    function_name = line.replace(source_line, '')
    function_name = function_name.replace("(https://)", '')
    # print("Function: ", function_name)
  elif "https://" in line:
    # Some stacktrace lines are present without any function names.
    # e.g https://localhost.corp.adobe.com:3000/libProteusWeb.js:14757:34
    function_name = pc_addr
    source_line = line.strip()

  if source_line:
    first_slash = source_line.find('/')
    file_line_col_substr = source_line[first_slash:]
    colon_positions = [pos for pos, char in enumerate(file_line_col_substr) if char == ':']
    file_name = file_line_col_substr[:colon_positions[0]]
    line_no = file_line_col_substr[colon_positions[0]+1 : colon_positions[1]]
    col_no = file_line_col_substr[colon_positions[1]+1 : ]
    #print("Source Info fileName:{0}, line_no: {1}, column_no:{2}".format(file_name, line_no, col_no))

  return LocationInfo(
    file_name,
    line_no,
    col_no,
    function_name
  )

def convert_pc_file_to_symbol_file(args):
  #print("convert_pc_file_to_symbol_file", args)
  pc_file = args.address
  # removing the new line characters
  with open(pc_file) as f:
      pcs = [line.rstrip() for line in f]
  #print("Number of addresses: {}".format(len(pcs)))

  out_sym_map_file = pc_file + ".symbol_map.json"
  #js_pc_map_file = "/Users/gmarella/Documents/SampleAppMemProfiling/JS_PC_CACHE.json"
  js_pc_map_file = "/Users/gmarella/Documents/VenusMemProfiling/obj_files/VENUS_JS_PC_CACHE.json"
  out_offset_convertet_map_file = pc_file +".offset_map.json"

  with open(js_pc_map_file, "r") as js_pc_file:
    JS_PC_MAP = json.load(js_pc_file)

  with webassembly.Module(args.wasm_file) as module:
    offsetConverter = wasm_offset_converter.WasmOffsetConverter(args.wasm_file, module)
    #offsetConverterMapFile = pc_file + ".offset_converter.json"
    #print(f'OffsetConverter Map to {offsetConverterMapFile}')
    #offsetConverter.printDetails()
    #offsetConverter.dumpLookUpMap(offsetConverterMapFile)
  
    with open(out_offset_convertet_map_file, "w") as out_offset_file:
      json.dump(offsetConverter.name_map, out_offset_file)
    sm = build_address_sourcemap(module, args.file, offsetConverter)
    pc_info = {}
    for pc in pcs:
      base = 16 if pc.lower().startswith('0x') else 10
      address_str = pc
      address = int(address_str, base)
      if isJSPC(address):
        address = getJSPC(address)

        pc_addr = str(address)
        if pc_addr in JS_PC_MAP:
          src = JS_PC_MAP[pc_addr]
          locInfo = get_location_info_from_line(src, pc_addr)
        else:
          locInfo = LocationInfo(
            "?",
            "?",
            "?",
            str(address)
          )
        #print("JS: address: {0}, source: {1}".format(hex(address), src))
        pc_info[address_str] = locInfo.getAsJson()
      else:
        symbolized = 0

        # if args.addrtype == 'code':
        #   address += get_codesec_offset(module)

        # print(f'has_debug_line_section?: ${has_debug_line_section(module)}')

        if ((has_debug_line_section(module) and not args.source) or
          'dwarf' in args.source):
          symbolize_address_dwarf(module, address)
          symbolized += 1

        if ((get_sourceMappingURL_section(module) and not args.source) or
          'sourcemap' in args.source):
          #print(sm.lookup(address))
          #addr_info = sm.lookup(address).getAsJson()
          addr_info = LocationInfo(
            "?",
            "?",
            "?",
            offsetConverter.getName(address)
          )

          # print(hex(address), addr_info)
          pc_info[address_str] = addr_info.getAsJson()
          symbolized += 1
          # print(f'Trying again for offset {hex(address)}')
          # address += get_codesec_offset(module)
          # addr_info2 = sm.lookup(address).getAsJson()
          # print(f'After offset addition: {hex(address)}, {addr_info2}')

        if not symbolized:
          raise Error('No .debug_line or sourceMappingURL section found in '
                      f'{module.filename}.'
                      " I don't know how to symbolize this file yet")
    # print("Writing symbols to {}".format(out_sym_map_file))
    with open(out_sym_map_file, 'w') as f:
      json.dump(pc_info, f)
      #pickle.dump(pc_info, f)


def main(args):
  if args.addrfile == 'file':
    convert_pc_file_to_symbol_file(args)
    return
  
  with webassembly.Module(args.wasm_file) as module:
    base = 16 if args.address.lower().startswith('0x') else 10
    address_str = args.address
    if address_str[-8] == "8":
      # TODO:Gopi; ust dumping random name for JS symbol, fix this properly.
      print(f'anonymous_js_function\n??:??:??')
      address_str = address_str[:-8] + '0' + address_str[-7:]
      return
    address = int(address_str, base)
    symbolized = 0
    offsetConverter = wasm_offset_converter.WasmOffsetConverter(args.wasm_file, module)

    if args.addrtype == 'code':
      address += get_codesec_offset(module)

    if ((has_debug_line_section(module) and not args.source) or
       'dwarf' in args.source):
      symbolize_address_dwarf(module, address)
      symbolized += 1

    if ((get_sourceMappingURL_section(module) and not args.source) or
       'sourcemap' in args.source):
      symbolize_address_sourcemap(module, address, args.file, offsetConverter)
      symbolized += 1

    if not symbolized:
      raise Error('No .debug_line or sourceMappingURL section found in '
                  f'{module.filename}.'
                  " I don't know how to symbolize this file yet")


def get_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('-s', '--source', choices=['dwarf', 'sourcemap'],
                      help='Force debug info source type', default=())
  parser.add_argument('-f', '--file', action='store',
                      help='Force debug info source file')
  parser.add_argument('-t', '--addrtype', choices=['code', 'file'],
                      default='file',
                      help='Address type (code section or file offset)')
  parser.add_argument('-v', '--verbose', action='store_true',
                      help='Print verbose info for debugging this script')
  parser.add_argument('wasm_file', help='Wasm file')
  # addr_group =  parser.add_mutually_exclusive_group()
  # addr_group.add_argument('address', help='Address to lookup', nargs='?')
  # addr_group.add_argument('address-file', help='Address File', nargs='?')
  parser.add_argument('address', help='Address to lookup or File containing addresses')

  parser.add_argument('-x', '--addrfile', choices=['code', 'file'],
                      default='code',
                      help='address is file or hexcode')

  args = parser.parse_args()
  if args.verbose:
    shared.PRINT_SUBPROCS = 1
    shared.DEBUG = True
  return args


if __name__ == '__main__':
  try:
    rv = main(get_args())
  except (Error, webassembly.InvalidWasmError, OSError) as e:
    print(f'{sys.argv[0]}: {str(e)}', file=sys.stderr)
    rv = 1
  sys.exit(rv)
