import os

from capstone import *

from config import RESULTS_FOLDER_PATH
from services import define_result_file_name


file_path = str(input("Inputh file path: "))

result_file_name = os.path.basename(file_path) + " disasm.txt"
result_file_name = define_result_file_name(result_file_name[::-1])

file_content = open(file_path, "rb").read()


# Disassembly file and write result in folder ..files/
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
# md.skipdata_setup = ("db", None, None)
# md.skipdata = True

with open(f"{RESULTS_FOLDER_PATH}{result_file_name}", "w") as result_file:
    for i in md.disasm(file_content, 0x1):
        result_file.write("0x{: <5} {: <8} {: <8}\n".format(
            i.address, i.mnemonic, i.op_str))
