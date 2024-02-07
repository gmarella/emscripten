#!/usr/bin/env python3

# This is a utility for looking up the symbol names for a list of addresses in
# a file. The addresses can be either PC addresses or JS PC addresses. The utility
# uses the VENUS_JS_PC_CACHE.json file to look up the symbol names for JS PC addresses.
# and offsetConverter to look up the symbol names for PC addresses.

# TODO: We need to use emsymbolizer.py to look up more info like line/file numbers.

import argparse
import json
import os
import re
import subprocess
import sys
import time
from tools import shared
from tools import webassembly
from tools import wasm_offset_converter


def run_command(command, cmd_stdin=None, cmd_stdout=None):
    start_time = time.time()
    result = subprocess.run(command, stdin=cmd_stdin, stdout=cmd_stdout)
    end_time = time.time()
    elapsed_time = "{:.2f}".format(end_time - start_time)
    print(f"############# \033[95m[TIMING]: {elapsed_time} seconds for Command {command}\033[0m")
    if result.returncode != 0:
        print(f"Command failed: {command}")
        sys.exit(1)


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

    def get_as_json(self):
        source = self.source if self.source else '??'
        func = self.func if self.func else '??'
        return {'source': source, 'func': func, 'line': self.line, 'column': self.column}


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


def is_js_pc(val):
    addr = '{:032b}'.format(val)
    return addr[0] == '1'


def get_js_pc(val):
    addr = '{:032b}'.format(val)
    addr = '0' + addr[1:]
    return int(addr, 2)


def get_location_info_from_line(line, pc_addr):
    m = re.search(r"\(https://(.+?)\)", line)
    file_name = "??"
    line_no = "??"
    col_no = "??"
    function_name = pc_addr
    source_line = None
    if m:
        source_line = m.group(1)
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
        line_no = file_line_col_substr[colon_positions[0] + 1:colon_positions[1]]
        col_no = file_line_col_substr[colon_positions[1] + 1:]
        # print("Source Info fileName:{0}, line_no: {1}, column_no:{2}".format(file_name, line_no, col_no))

    return LocationInfo(
        file_name,
        line_no,
        col_no,
        function_name
    )


def demangle_function_names(pc_info, out_dir, args):
    # Extract the function names from the symbol map and write to a file named orig_function_names.txt
    orig_function_names_file = os.path.join(out_dir, "orig_function_names.txt")
    PC_FILENAME_SEPARATOR = " #### "
    DEMANGLE_SCRIPT = os.path.join(args.llvm_bin_path, "llvm-cxxfilt")
    with open(orig_function_names_file, "w") as f:
        for pc in pc_info:
            func_name = pc_info[pc]['func']
            f.write(f"{pc}{PC_FILENAME_SEPARATOR}{func_name}\n")
    """
        Run the demangler script at args.llvm_bin_path/llvm-cxxfilt to demangle the function names.
    """
    demangled_function_names_file = os.path.join(out_dir, "demangled_function_names.txt")
    with open(demangled_function_names_file, "w") as f:
        cmd = [DEMANGLE_SCRIPT, "-n"]
        run_command(cmd, cmd_stdin=open(orig_function_names_file), cmd_stdout=f)

    """
        update the symbol map with the demangled function names.
    """
    demangled_names = {}
    with open(demangled_function_names_file, "r") as f:
        for line in f:
            pc, demangled_func_name = line.split(PC_FILENAME_SEPARATOR)
            pc = pc.strip()
            demangled_names[pc] = demangled_func_name.strip()
    for pc in pc_info:
        pc_info[pc]['func'] = demangled_names[pc]
    return pc_info


def convert_pc_file_to_symbol_file(args):
    # print("convert_pc_file_to_symbol_file", args)
    pc_file = args.pc_file
    # removing the new line characters
    with open(pc_file) as f:
        pcs = [line.rstrip() for line in f]
    # print("Number of addresses: {}".format(len(pcs)))

    out_sym_map_file = pc_file + ".symbol_map.json"
    print("Writing symbols to {}".format(out_sym_map_file))
    OUT_DIR = os.path.dirname(pc_file)
    js_pc_map_file = os.path.join(OUT_DIR, "VENUS_JS_PC_CACHE.json")
    out_offset_convertet_map_file = pc_file + ".offset_map.json"

    with open(js_pc_map_file, "r") as js_pc_file:
        JS_PC_MAP = json.load(js_pc_file)

    offset_converter = None
    with webassembly.Module(args.wasm_file) as module:
        offset_converter = wasm_offset_converter.WasmOffsetConverter(args.wasm_file, module)
    if not offset_converter:
        print(f'Failed to create offset converter for {args.wasm_file}')
        sys.exit(1)

    with open(out_offset_convertet_map_file, "w") as out_offset_file:
        json.dump(offset_converter.name_map, out_offset_file)
    pc_info = {}
    for pc in pcs:
        base = 16 if pc.lower().startswith('0x') else 10
        address_str = pc
        address = int(address_str, base)
        if is_js_pc(address):
            address = get_js_pc(address)

            pc_addr = str(address)
            if pc_addr in JS_PC_MAP:
                src = JS_PC_MAP[pc_addr]
                loc_info = get_location_info_from_line(src, pc_addr)
            else:
                loc_info = LocationInfo(
                    "?",
                    "?",
                    "?",
                    str(address)
                )
            pc_info[address_str] = loc_info.get_as_json()
        else:
            # TODO: If we need line number info, and we can either go with DWARF or sourcemap
            addr_info = LocationInfo(
                "?",
                "?",
                "?",
                offset_converter.getName(address)
            )

            pc_info[address_str] = addr_info.get_as_json()
            # print(f'Trying again for offset {hex(address)}')
            # address += get_codesec_offset(module)
            # addr_info2 = offset_converter.get_name(address)
            # print(f'After offset addition: {hex(address)}, {addr_info2}')

    # Demangle the C++ function names.
    pc_info = demangle_function_names(pc_info, OUT_DIR, args)
    # Write the updated symbol map to the output file.
    with open(out_sym_map_file, 'w') as f:
        json.dump(pc_info, f)


def main(args):
    convert_pc_file_to_symbol_file(args)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print verbose info for debugging this script')
    parser.add_argument('wasm_file', help='Wasm file')
    parser.add_argument('pc_file', help='File containing list of PC addresses')
    # Add argument for LLVM bin path with "~/.venus_emscripten/upstream/bin" as default value.
    parser.add_argument('--llvm_bin_path', default=os.path.expanduser("~/.venus_emscripten/upstream/bin"),
                        help='Path to LLVM bin directory')

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
