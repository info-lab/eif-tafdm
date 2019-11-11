import struct


class AbstractDump:
    def __init__(self, path, archclass):
        self.dirbase = 0
        self.process_head = 0
        self.arch = archclass(self)
    
    def __repr__(self):
        return "\n".join([
            self.__class__.__name__,
            "\tDirBase: " + hex(self.dirbase),
        ])

    def read(self, pos, length):
        pass

    def vtop(self, addr, debug=False):
        return self.arch.vtop(addr, debug)


# Analice el funcionamiento de esta clase para entender cómo maneja el acceso
# al volcado
class RawDump(AbstractDump):
    def __init__(self, path, archclass):
        super().__init__(path, archclass)
        self.mem = open(path, "rb")
    
    def read(self, pos, length):
        self.mem.seek(pos)
        return self.mem.read(length)


        
# Una excepción especial para el caso de tratar de leer una posición que no
# está mapeada por los runs del CrashDump.
class OutsideRangesException(Exception):
    pass


class CrashDump(AbstractDump):
    def __init__(self, path, archclass):
        # En el caso de CrashDump hay que incorporar el parsing de los primeros
        # 4KiB (serían 8KiB en el caso de CrashDump64)
        # De este encabezado se casa información valiosa, incluyendo el DTB (o
        # DirBase).
        # Hay que parsear también los rangos de los Runs, para poder manejar
        # adecuadamente las lecturas.
        super().__init__(path, archclass)
        self.mem = open(path, "rb")
        self.st_uint32 = struct.Struct("<L")
        # Ahora hay que parsear el encabezado del CrashDump para sacar los
        # punteros de interés e interpretar la lista de runs.
        raw_header = self.mem.read(4096)
        self._raw_header = raw_header
        self.dirbase, = self.st_uint32.unpack(raw_header[0x10: 0x14])
        self.process_head, = self.st_uint32.unpack(raw_header[0x1c: 0x20])
        runs = raw_header[0x64:0x320]
        st_parseruns = struct.Struct("<2L")
        self.ranges = []
        fpos = 1 << 12  # efectivamente es 4096, se busca hacer un poco más
                        # explícito que estamos hablando de un offset en
                        # páginas dentro del volcado
        nruns, last_page = st_parseruns.unpack(runs[0:8])
        for i in range(1, nruns + 1):
            start_addr, length = st_parseruns.unpack(runs[i*8: i*8 + 8])
            start_addr *= 4096
            length *= 4096
            self.ranges.append((fpos, start_addr, length))
            fpos += length

    
    def read(self, pos, length):
        # Tenemos que buscar sobre qué run se mapea la posición que se busca
        # leer -- la búsqueda lineal no es el método más rápido pero es simple
        for fpos, saddr, rlength in self.ranges:
            if saddr > pos:
                raise OutsideRangesException(
                    "Tried to read: %s - (saddr: %s)" % (hex(pos), hex(saddr))
                )
            if saddr <= pos <= saddr + rlength:
                break  # encontramos el run que contiene la posición buscada
        # print("Page in dump : %s" % hex(fpos))
        fpos = fpos + (pos - saddr)  # nos ubicamos en el offset
        # print("Offset to    : %s" % hex(fpos))
        self.mem.seek(fpos)
        return self.mem.read(length)