import struct


# En primer lugar, definimos una clase abstracta para estandarizar la interfaz
# de las clases que manejan el acceso a los dumps. Las clases que heredan de
# AbstractDump son las que controlan el acceso al volcado de memoria en última
# instancia, y varían según el formato del mismo.

class AbstractArch:
    def __init__(self, mem):
        self.mem = mem
    
    def vtop(self, addr, debug=False):
        raise NotImplementedError
    
    
    def parse_vaddr(self, addr):
        raise NotImplementedError
    
    
    def __repr__(self):
        return f"{self.__class__.__name__}"


class ArchX86(AbstractArch):
    def __init__(self, mem):
        super().__init__(mem)
        self.st_uint32 = struct.Struct("<L")

    def vtop(self, addr, debug=False):
        # Así como está implementada la función, no revisa los flags que se
        # encuentran presentes en el PDE y el PTE, asique no maneja las large
        # pages, ni tampoco interpreta el valid bit
        st = self.st_uint32
        mem = self.mem
        dbase = mem.dirbase
        pdi, pti, offset = self.parse_vaddr(addr)
        pde, = st.unpack(mem.read(dbase + pdi * 4, 4))
        pde  = pde  & 0xfffff000 
        pte, = st.unpack(mem.read(pde   + pti * 4, 4))
        pte  = pte  & 0xfffff000
        paddr = pte + offset
        # Principalmente sirvieron para debugging, pero estos prints pueden
        # resultar útiles para ver cómo es la traducción de direcciones.
        if debug:
            print(f"Virtual Addr: {hex(addr)}")
            print(f"Parsed as:")
            print(f"\n".join([f"--PDI  : {hex(pdi)}",
                              f"--PTI  : {hex(pti)}",
                              f"--OFFS : {hex(offset)}",
                            ]))
            print(f"PDE  : {hex(pde)}")
            print(f"PTE  : {hex(pte)}")
        return paddr
    
    
    def parse_vaddr(self, addr):
        # 0b 0000 0000 0000 0000 0000 0000 0000 0000
        # 0b 1111 1111 1100 0000 0000 0000 0000 0000
        # 0b 0000 0000 0011 1111 1111 0000 0000 0000
        pdi  = (addr & 0xffc00000) >> 22
        pti  = (addr & 0x003ff000) >> 12
        offs =  addr & 0x00000fff
        return pdi, pti, offs

        
class ArchX86PAE(ArchX86):
    def vtop(self, addr, debug=False):
        # Usando como base ArchX86.vtop(), implemente la función de traducción
        # de direcciones virtuales a físicas en x86 con PAE.
        
        # encuentran presentes en el PDE y el PTE, asique no maneja las large
        # pages, ni tampoco interpreta el valid bit
        st = self.st_uint32
        mem = self.mem
        dbase = mem.dirbase
        pdpi, pdi, pti, offset = self.parse_vaddr(addr)
        # reemplace estas asignaciones por las correspondientes de acuerdo
        # con el mecanismo de traducción de direcciones y el ejemplo de 
        # ArchX86
        pdpe  = 0
        pde   = 0
        pte   = 0
        paddr = 0
        # Principalmente sirvieron para debugging, pero estos prints pueden
        # resultar útiles para ver cómo es la traducción de direcciones.
        if debug:
            print(f"Virtual Addr: {hex(addr)}")
            print(f"Parsed as:")
            print(f"\n".join([f"--PDPI : {hex(pdpi)}",
                              f"--PDI  : {hex(pdi)}",
                              f"--PTI  : {hex(pti)}",
                              f"--OFFS : {hex(offset)}",
                            ]))
            print(f"PDPE : {hex(pdpe)}")
            print(f"PDE  : {hex(pde)}")
            print(f"PTE  : {hex(pte)}")
        return paddr
    
    
    # Si bien parse_virtual_address podría ser reemplazada (inline), resulta más
    # cómodo que esté de manera aislada.
    def parse_vaddr(self, addr):
        # implemente el parseo de las direcciones virtuales en sus distintos
        # índices, de acuerdo a lo visto en el contenido teórico
        # puede consultar con el código de ArchX86 para ver cómo realizar
        # el parse en el caso sin PAE
        pdpi = 0
        pdi  = 0
        pti  = 0
        offs = 0
        return pdpi, pdi, pti, offs