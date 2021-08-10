import os
import pathlib
import zipfile
import magic
import platform

from capstone import *

from config import PATH_OF_RESULTS_FOLDER, PATH_OF_EXTRACTED_ARCHIVES_FOLDER


def open_file(file_path: str) -> str:
    try:
        file_content = open(file_path, "rb").read()
        return file_content
    except FileNotFoundError:
        print(f"Error! File {file_path} doesn't exists!")


def disasm_with_dex2jar(file_path: str, result_folder_name: str = None) -> None:
    if result_folder_name != None:
        result_folder_name += "/"
    else:
        result_folder_name = ""
    file_full_name = pathlib.Path(file_path).name
    smali_result_folder_name = file_full_name + "_classes.dex/"
    if "Windows" in platform.system():
        os.system(
            f"..\dex2jar-2.0\d2j-baksmali.bat {file_path} -o {PATH_OF_RESULTS_FOLDER}{result_folder_name}{smali_result_folder_name}")
    else:
        os.system(
            f"../dex2jar-2.0/d2j-baksmali.sh {file_path} -o {PATH_OF_RESULTS_FOLDER}{result_folder_name}{smali_result_folder_name}")


def disasm_with_jadx(file_path: str, result_folder_name: str = None) -> None:
    file_content = open_file(file_path)
    file_type = magic.from_buffer(file_content)
    print("file_path: ", file_path, "\nfile_type: ", file_type)

    result_folder_name_java_files = ""
    if result_folder_name != None:
        result_folder_name += "/"
        file_full_name = pathlib.Path(file_path).name
        result_folder_name_java_files = file_full_name + "_java_files/"
    else:
        result_folder_name = ""
    if "Windows" in platform.system():
        os.system(
            rf"..\jadx-1.2.0\bin\jadx {file_path} -d {PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_folder_name_java_files}")
    else:
        os.system(
            rf"../jadx-1.2.0/bin/jadx {file_path} -d {PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_folder_name_java_files}")


def define_md_options(file_path: str) -> Cs:
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    file_content = open_file(file_path)
    file_type = magic.from_buffer(file_content)
    if "ARM" in file_type:
        if "32-bit" in file_type:
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
        elif"64-bit" in file_type:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM64, CS_MODE_ARM")
    if "Intel" in file_type:
        if "16-bit" in file_type or "MS-DOS executable" in file_type or "NE for MS Windows" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_16)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_16")
        elif "32-bit" in file_type or "Intel 80386" in file_type or "x86-32" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_32")
        elif "64-bit" in file_type or "x86-64" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_64")
    md.skipdata_setup = ("db", None, None)
    md.skipdata = True
    return md


def disasm_and_save_result(file_path: str, result_folder_name: str = None) -> None:
    # Setting disasm with capstone options on md
    md = define_md_options(file_path)
    first_disasm_mode = md.mode

    # Disasm and saving result in {result_folder_path}
    if result_folder_name == None:
        result_folder_name = ""
    result_file_name = pathlib.Path(file_path).name + ".asm"
    result_folder_path = f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_file_name}"
    with open(result_folder_path, "w") as result_file:
        file_content = open_file(file_path)
        for (address, size, mnemonic, op_str) in md.disasm_lite(file_content, 0x1):
            # Changing disasm MODE
            if mnemonic in ("bx", "blx"):
                md.mode = CS_MODE_THUMB
            elif mnemonic == "rev":
                if md.mode == first_disasm_mode + CS_MODE_BIG_ENDIAN:
                    md.mode = first_disasm_mode + CS_MODE_LITTLE_ENDIAN
                elif md.mode == first_disasm_mode + CS_MODE_LITTLE_ENDIAN:
                    md.mode = first_disasm_mode + CS_MODE_BIG_ENDIAN
            result_file.write("0x{: <5} {: <8} {: <8}\n".format(address,
                                                                mnemonic, op_str))
    print(f"Result of the disasm file in {result_folder_path}", "\n")
