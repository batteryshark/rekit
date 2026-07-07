# Ghidra headless post-script (runs inside Ghidra's Jython, NOT host python).
# Decompiles every function in the imported program to a single C file.
#
# Invoked by run.py as: analyzeHeadless ... -postScript ghidra_decompile.py <outpath>
# Ghidra provides the globals `currentProgram`, `getScriptArgs()`, etc.
# @category unmask

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()  # noqa: F821 (Ghidra global)
out_path = args[0] if args else "decompiled.c"

ifc = DecompInterface()
ifc.openProgram(currentProgram)  # noqa: F821 (Ghidra global)
monitor = ConsoleTaskMonitor()
fm = currentProgram.getFunctionManager()  # noqa: F821

fh = open(out_path, "w")
try:
    count = 0
    for func in fm.getFunctions(True):
        res = ifc.decompileFunction(func, 60, monitor)
        if res is not None and res.decompileCompleted():
            dec = res.getDecompiledFunction()
            if dec is not None:
                fh.write(dec.getC())
                fh.write("\n")
                count += 1
    print("unmask: decompiled %d function(s) -> %s" % (count, out_path))
finally:
    fh.close()
