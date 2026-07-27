# Ghidra headless post-script (runs inside Ghidra's Jython, NOT host python).
# Writes the analysed program to a BinExport v2 file for BinDiff.
#
# Invoked by run.py as: analyzeHeadless ... -postScript ghidra_binexport.py <outpath>
# Requires the BinExport Ghidra extension to be installed (it supplies the
# com.google.security.binexport classes); run.py checks for it first and reports
# the install hint when it is missing.
#
# `Subtract Imagebase` and IDA-style mnemonics are applied so that exports from
# Ghidra and from IDA Pro diff against each other sensibly.
# @category rekit

from java.io import File, FileOutputStream

from com.google.security.binexport import BinExport2Builder, IdaProMnemonicMapper

args = getScriptArgs()  # noqa: F821 (Ghidra global)
if not args:
    raise ValueError("ghidra_binexport.py: missing output path argument")
out_path = args[0]

program = currentProgram  # noqa: F821 (Ghidra global)
builder = BinExport2Builder(program, program.getMemory())
builder.setMnemonicMapper(IdaProMnemonicMapper(program.getLanguage()))
builder.setAddressOffset(program.getImageBase().getOffset())

proto = builder.build()
stream = FileOutputStream(File(out_path))
try:
    proto.writeTo(stream)
finally:
    stream.close()

print("rekit: wrote BinExport -> %s" % out_path)
