import os
import sys

from capstone import *
from capstone.arm import *

from config import RESULTS_FOLDER_PATH


def define_result_file_name(result_file_name: str) -> str:

    file_name = result_file_name[result_file_name.find(".")+1:]
    file_name = file_name[::-1]

    if result_file_name.find(".") != -1:
        file_extension = result_file_name[:result_file_name.find(".")]
        file_extension = file_extension[::-1]
    else:
        file_extension = ""

    result_file_name = file_name + "." + file_extension

    # Define file name. If this file name exists: file name += "file_name (копия name_counter).file_extension"
    name_counter = 0
    while True:
        if result_file_name in os.listdir(f"{RESULTS_FOLDER_PATH}"):
            file_name = file_name.replace(f" (копия {name_counter})", "")
            name_counter += 1
            file_name += f" (копия {name_counter})"
            result_file_name = file_name + "." + file_extension
        else:
            break

    return result_file_name


def disasm_and_save_result(md, result_file_name, file_content) -> None:
    print(f"Capstone start options: {md.arch}, {md.mode}")

    first_mode = md.mode
    md.skipdata_setup = ("db", None, None)
    md.skipdata = True

    with open(f"{RESULTS_FOLDER_PATH}{result_file_name}", "w") as result_file:

        for (address, size, mnemonic, op_str) in md.disasm_lite(file_content, 0x1):

            # Change disasm MODE
            if mnemonic in ("bx", "blx"):
                md.mode = CS_MODE_THUMB

            if mnemonic == "rev":
                if md.mode == first_mode + CS_MODE_BIG_ENDIAN:
                    md.mode = first_mode + CS_MODE_LITTLE_ENDIAN
                elif md.mode == first_mode + CS_MODE_LITTLE_ENDIAN:
                    md.mode = first_mode + CS_MODE_BIG_ENDIAN

            result_file.write("0x{: <5} {: <8} {: <8}\n".format(
                address, mnemonic, op_str))

    print(
        f"Result of the disasm file in {RESULTS_FOLDER_PATH}{result_file_name}")
    sys.exit()
