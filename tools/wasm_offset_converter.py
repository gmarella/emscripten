from tools import webassembly
import json
# 
"""
Python version of wasm_offset_converter.js
- Support to build offset-function-name map is added to the webassembly.py itself unlike .js file.
"""
class WasmOffsetConverter:
    def __init__(self, wasmFile, wasmModule):
        # map from function index to byte offset in WASM binary
        self.offset_map = {}
        self.func_starts = []
        # map from function index to names in WASM binary
        # number of imported functions self module has
        self.import_functions = 0
        with open(wasmFile, "rb") as f_h:
            self.buffer = bytearray(f_h.read())
        self.wasmModule = wasmModule
        self.name_map = self.wasmModule.get_function_names()
        self.parse_buffer()

    def parse_buffer(self):
        # the buffer unsignedLEB128 will read from.
        buffer = self.buffer
        offset = 8
        funcidx = 0

        def unsignedLEB128():
            # consumes an unsigned LEB128 integer starting at `offset`.
            # changes `offset` to immediately after the integer
            nonlocal offset
            result = 0
            shift = 0
            while True:
                byte = buffer[offset]
                offset += 1
                result += (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
            return result

        def skipLimits():
            flags = unsignedLEB128()
            unsignedLEB128() # initial size
            hasMax = (flags & 1) != 0
            if hasMax:
                unsignedLEB128()

        continue_parsing = True
        while continue_parsing and offset < len(buffer):
            start = offset
            type = buffer[offset]
            offset += 1
            end = unsignedLEB128() + offset
            if type == 2:  # import section
                count = unsignedLEB128()
                while count > 0:
                    offset = unsignedLEB128() + offset
                    offset = unsignedLEB128() + offset
                    kind = buffer[offset]
                    offset = offset + 1
                    if kind == 0:
                        funcidx = funcidx + 1
                        unsignedLEB128()
                    elif kind == 1:
                        unsignedLEB128()
                        skipLimits()
                    elif kind == 2:
                        skipLimits()
                    elif kind == 3:
                        offset = offset + 2
                    elif kind == 4:
                        offset = offset + 1
                        unsignedLEB128()
                    else:
                        raise Exception('bad import kind: ' + str(kind))
                    count = count - 1
                self.import_functions = funcidx
            elif type == 10:  # code section
                count = unsignedLEB128()
                while count > 0:
                    size = unsignedLEB128()
                    self.offset_map[funcidx] = offset
                    funcidx += 1
                    self.func_starts.append(offset)
                    offset += size
                    count -= 1
                continue_parsing = False
            offset = end

    def convert(self, funcidx, offset):
        return self.offset_map[funcidx] + offset

    def getIndex(self, offset):
        lo = 0
        hi = len(self.func_starts)
        mid = 0
        while lo < hi:
            mid = (lo + hi) // 2
            if self.func_starts[mid] > offset:
                hi = mid
            else:
                lo = mid + 1
        if lo == len(self.func_starts):
            return -1
        return lo + self.import_functions - 1

    def isSameFunc(self, offset1, offset2):
        return self.getIndex(offset1) == self.getIndex(offset2)
    
    def printLookupMap(self):
        print("wasmOffsetConverter lookup map\n")
        print(self.name_map)

    def printDetails(self):
        print("wasmOffsetConverter details\n")
        print(f'NameMap entries: {len(self.name_map)}, ImportedFunctions: {self.import_functions}, OffsetMap: {len(self.offset_map)}')

    def dumpLookUpMap(self, filePath):
        with open(filePath, 'w') as fileHandle:
            json.dump(self.name_map, fileHandle)

    def lookupIndexFromName(self, fname):
        for key, value in self.name_map.items():
            if fname in value:
                return [key, value, hex(self.offset_map[key])]
        return [None, None, None]

    def getName(self, offset):
        index = self.getIndex(offset)
        lookup_map = self.name_map
        return lookup_map[index] if index in lookup_map else ('wasm-function[' + str(index) + ']')
