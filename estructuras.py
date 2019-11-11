import datetime
import struct


def wintime(raw):
    """Parsea los bytes (en raw) de un LARGE_INTEGER para obtener una fecha/hora
    en formato Windows.
    """
    lo, hi = struct.unpack("<LL", raw)
    value = (hi << 32) + lo
    # este algoritmo es el que implementamos en FileValidators para hacer el
    # manejo de las fechas en formato Windows NT
    tics = value
    days = tics // 864_000_000_000
    rem = tics - days * 864_000_000_000
    hours = rem // 36_000_000_000
    rem -= hours * 36_000_000_000
    minutes = rem // 600_000_000
    rem -= minutes * 600_000_000
    seconds = rem // 10_000_000
    rem -= seconds * 10_000_000
    microseconds = rem // 100
    td = datetime.timedelta(days)  # así se manejan fácil los bisiestos
    hours, minutes, seconds, microseconds = map(int, [hours, minutes, seconds, microseconds])
    retval = datetime.datetime(1601, 1, 1, hours, minutes, seconds, microseconds) + td
    if value == 0:
        retval = None
    return retval


# Implemente las clases para representar los procesos en memoria. Vea las
# estructuras EPROCESS y sus estructuras embebidas con WinDbg. El comando que 
# debe utilizar dt. Por ejemplo, para ver _EPROCEES debe ingresar:
#   dt !_eprocess
# Considere la función pretty_pslist() para decidir qué campos debe parsear de
# la estructura _EPROCESS.


class EProcess:

    fullsize = 0x2d8

    def __init__(self, rawdata, base_addr=0):
        self.base_addr = base_addr
        self.pcb = KProcess(rawdata[0x0: 0x98])
        self.active_process_links = ListEntry(rawdata[0xb8: 0xb8 + 8])
        image_name, = struct.unpack("<15s", rawdata[0x16c: 0x16c + 15])
        self.image_name = (image_name.replace(b"\x00", b"")).decode("ascii")
        self.pid, = struct.unpack("<L", rawdata[0xb4: 0xb8])
        self.create_time = wintime(rawdata[0xa0: 0xa8])
        self.exit_time = wintime(rawdata[0xa8: 0xb0])
        

    
    def __repr__(self):
        return f"Process '{self.image_name}' @ {hex(self.base_addr)}"


class ListEntry:

    fullsize = 0x8

    def __init__(self, rawdata):
        self.flink, self.blink = struct.unpack("<2L", rawdata)
    
    def __repr__(self):
        return f"ListEntry - FLink: {hex(self.flink)} BLink: {hex(self.blink)}"


class KProcess:
    
    fullsize = 0x98
    
    def __init__(self, rawdata):
        self.dispatcher_header = DispatcherHeader(rawdata[0x0: 0x10])
        self.profile_list_head = ListEntry(rawdata[0x10: 0x18])
        self.directory_table_base, = struct.unpack("<L", rawdata[0x18: 0x1c])
    
    def __repr__(self):
        return "< KProcess >"


class DispatcherHeader:
    
    fullsize = 0x10
    
    def __init__(self, rawdata):
        pass
    
    def __repr__(self):
        return "< Dispatcher Header >"