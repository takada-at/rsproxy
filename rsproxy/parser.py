# coding:utf-8

import base64
import struct

struct_compile = getattr(struct, 'Struct', None) or struct._compile
_fmt_int32 = struct_compile('!I')
_fmt_int16 = struct_compile('!H')
pack_int32 = _fmt_int32.pack
unpack_int32 = _fmt_int32.unpack
unpack_int16 = _fmt_int16.unpack
unpack_int32_from = _fmt_int32.unpack_from
unpack_int16_from = _fmt_int16.unpack_from

class Buffer(object):
    def __init__(self, data=None):
        self.buf = '' if data is None else data
        self.pos = 0
    def append(self, data):
        self.buf += data
    def reset(self):
        self.pos = 0
    def get_char(self):
        p = self.pos
        self.pos += 1
        return self.buf[p]
    def get_int16(self):
        p = self.pos
        self.pos += 2
        return unpack_int16_from(self.buf, p)[0]
    def get_int32(self):
        p = self.pos
        self.pos += 4
        return unpack_int32_from(self.buf, p)[0]
    def __getitem__(self, i):
        return ord(self.buf[i])
    def __len__(self):
        return len(self.buf)
    def raw_value(self):
        return self.buf
    def remainder(self):
        return self.buf[self.pos:]
    def remainder_length(self):
        return len(self.buf) - self.pos
    def truncate(self, length):
        extra = self.buf[length:]
        self.buf = self.buf[:length]
        return extra

class Parser(object):
    def __init__(self):
        self.buffer = Buffer()
        self.parsed_header = False
        self.type = ''
        self.length = -1
    def consume(self, data):
        self.buffer.append(data)

        if not self.parse_header():
            return False, ''

        if len(self.buffer) < self.length:
            return False, ''

        self.extra = self.buffer.truncate(self.length)
        self.parse_body()
        return True, self.extra
    def parse_header(self):
        if self.parsed_header:
            return True
        if self.buffer.remainder_length() < 5:
            return False
        t = self.buffer.get_char()
        if ord(t) != 0:
            self.type = t
            self.length = self.buffer.get_int32() + 1
        else:
            if not self.parse_special_header():
                return False
        self.parsed_header = True
        return True
    def parse_special_header(self):
        u"""
        Frontend/Backendで実装
        """
        self.raise_unknown()
    def parse_body(self):
        def nothing():
            pass

        self.data = self.buffer.raw_value()[self.buffer.pos:self.length]
        getattr(self, 'parse_' + self.type, nothing)()
    def raise_unknown(self):
        raise ValueError(
            'Unknown %s packet: %r' % (
                self.__class__.__name__, 
                self.buffer.raw_value()[:200]))
    def serialize(self):
        return self.buffer.raw_value()[:self.length]
    def parseDict(self, data=None):
        data = data or self.data
        params = [x for x in data.split('\x00') if x]
        return dict([(k, v) for k, v in zip(params[::2], params[1::2])])
    def __str__(self):
        return getattr(self, 'str_' + self.type, lambda: self.type)() #+ ":" + base64.b64encode(self.buffer.raw_value())

class FrontendParser(Parser):
    Cancel = 80877102
    SSLRequest = 80877103
    def parse_Startup(self):
        self.parameters = self.parseDict()
    def parse_Cancel(self):
        self.pid = self.buffer.get_int32()
        self.key = self.buffer.get_int32()
    def parse_C(self):
        self.kind = 'prepared' if self.buffer.get_char() == 'S' else 'portal'
    def parse_p(self):
        self.password = self.buffer.remainder()[:-1]
    def parse_special_header(self):
        if self.buffer.remainder_length() < 7:
            self.buffer.reset()
            return False

        self.buffer.get_char()
        self.length = self.buffer.get_int16()
        code = self.buffer.get_int32()

        if code == FrontendParser.Cancel:
            self.type = 'Cancel'
        elif code == FrontendParser.SSLRequest:
            self.type = 'SSLRequest'
        elif self.is_startup_code(code):
            self.type = 'Startup'
        else:
            self.raise_unknown()

        return True
    def is_startup_code(self, code):
        return (code >> 16) == 3 and (code & 0xffff) < 2
    def str_Q(self):
        return 'Q %s' % self.data[:-1]

class BackendParser(Parser):
    def parse_R(self):
        self.status = self.buffer.get_int32()
        self.success = (self.status == 0)
    def parse_Z(self):
        self.transaction_status = {
            'I': 'idle',
            'E': 'failed',
            'T': 'transaction',
            }.get(self.buffer.get_char())
    def parse_S(self):
        self.name, self.value = self.data.split('\x00')[:2]
    def parse_E(self):
        code = ord(self.buffer.get_char())
        self.fields = []
        if code:
            for f in self.data.split('\x00'):
                if not f:
                    continue
                self.fields.append((f[0], f[1:]))
    def str_S(self):
        return 'S %s = %s' % (self.name, self.value)
    def str_C(self):
        return 'C[%s]' % self.data[:-1]
    def str_E(self):
        return 'E - %r' % self.fields

def terminate():
    """
    Constructs a new Terminate message. 
    """
    m = FrontendParser()
    m.consume('X\x00\x00\x00\x04')
    return m

