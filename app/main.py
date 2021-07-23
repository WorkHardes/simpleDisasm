import os
import magic

from capstone import *

from config import RESULTS_FOLDER_PATH
from services import define_result_file_name, disasm_and_save_result


def main():
    # Open file
    while True:
        file_path = "../files/4_32.exe"
        # file_path = str(input("Inputh file path: "))
        try:
            file_content = open(file_path, "rb").read()
            file_type = magic.from_buffer(file_content)
            break
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")

    result_file_name = os.path.basename(file_path) + " disasm.txt"
    result_file_name = define_result_file_name(result_file_name[::-1])

    print("Filetype: ", file_type)
    # Disassembly file and write result in folder ..files/
    if "ARM" in file_type and "32-bit" in file_type or "Zip archive data" in file_type:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        print("Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
        disasm_and_save_result(md, result_file_name, file_content)

    if "ARM" in file_type and "64-bit" in file_type:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        print("Capstone start options: CS_ARCH_ARM64, CS_MODE_ARM")
        disasm_and_save_result(md, result_file_name, file_content)

    if "Intel" in file_type and "16-bit" in file_type or "MS-DOS executable" in file_type or "NE for MS Windows" in file_type:
        md = Cs(CS_ARCH_X86, CS_MODE_16)
        print("Capstone start options: CS_ARCH_X86, CS_MODE_16")
        disasm_and_save_result(md, result_file_name, file_content)

    if "Intel" in file_type and "32-bit" in file_type or "Intel 80386" in file_type or "x86-32" in file_type:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        print("Capstone start options: CS_ARCH_X86, CS_MODE_32")
        disasm_and_save_result(md, result_file_name, file_content)

    if "Intel" in file_type and "64-bit" in file_type or "x86-64" in file_type:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        print("Capstone start options: CS_ARCH_X86, CS_MODE_64")
        disasm_and_save_result(md, result_file_name, file_content)


if __name__ == "__main__":
    main()
