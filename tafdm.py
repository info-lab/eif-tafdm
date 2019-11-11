import datetime
import struct

from archs import *
from dumps import *
from estructuras import *


def pretty_pslist(plist, fields=None):
    if fields is None:  # esta es una forma de manejar el argumento por defecto
        fields = [
            ("pid", "PID", 8),
            ("image_name", "Name", 15),
            ("create_time", "Create Time", 30),
            ("exit_time", "Exit Time", 30),
        ]
    attr, name, col_len = fields[0]
    header = " ".join([(r"%-"+("%d" % f[2]) + "s") % f[1] for f in fields])
    headli = " ".join(["-" * f[2] for f in fields])
    proto  = " ".join([(r"%-"+("%d" % f[2]) + "s") for f in fields])
    print(header)
    print(headli)
    for ps in plist:
        print(proto % tuple([getattr(ps, f[0]) for f in fields]))


# Implemente la función pslist()
def pslist(dump):
    # desde el dump (asumimos  un volcado CrashDump, o que el usuario ha cargado
    # la dirección del primer proceso en el atributo dump.process_head) se lee
    # la dirección (virtual) del primer proceso
    pslist_head = dump.process_head
    # instanciamos una lista vacía para ir cargando cada uno de los procesos
    # en ella (esta es la variable de retorno)
    ret = []
    # por comodidad, guardamos en una variable auxiliar el tamaño de la
    # estructura de proceso
    psize = EProcess.fullsize

    next_ps = ListEntry(dump.read(dump.vtop(pslist_head), 8))

    # complete el ciclo while para recorrer la lista (doblemente enlazada) de
    # procesos en memoria
    while True:  # modifique la condición
        # para instanciar un proceso, utilice la clase EProcess, que recibe:
        #   * un conjunto de bytes, del tamaño psize
        #      * estos bytes provienen de la dirección de memoria del proceso
        #        por lo tamnto debe hacer un dump.read -- y recuerde que trabaja
        #        con direcciones virtuales
        #   * una baseaddr (entero, opcional) que es la dirección en memoria del
        #     proceso -- es útil completar este campo porque ayuda a buscarlo
        #     con otras herramientas
        ps = EProcess(
            b"",
            0x00
        )
        # una vez instanciado el proceso, se lo agrega a la lista de procesos
        ret.append(ps)
        # no se olvide de seguir los links de la lista de procesos
    return ret
