import os
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


def get_file_name(file_full_name: str) -> str:
    file_full_name = file_full_name[::-1]
    if file_full_name.find("/") > -1:
        file_name = file_full_name[file_full_name.find(
            ".")+1:file_full_name.find("/")]
    else:
        file_name = file_full_name[file_full_name.find(
            ".")+1:]
    file_name = file_name[::-1]
    return file_name


def get_file_extension(file_full_name: str) -> str:
    file_full_name = file_full_name[::-1]
    if file_full_name.find(".") != -1:
        file_extension = file_full_name[:file_full_name.find(".")]
        file_extension = file_extension[::-1]
    else:
        file_extension = ""
    return file_extension


def define_result_file_or_folder_name(file_full_name: str) -> str:
    file_name = get_file_name(file_full_name)
    file_extension = get_file_extension(file_full_name)
    result_file_name = file_name + "." + file_extension
    # Defining the file name in results folder by setting (копия X) if it exists
    copy_number_counter = 0
    while True:
        if result_file_name in os.listdir(f"{PATH_OF_RESULTS_FOLDER}"):
            file_name = file_name.replace(
                f"_(копия {copy_number_counter})", "")
            copy_number_counter += 1
            file_name += f"_(копия {copy_number_counter})"
            result_file_name = file_name + "." + file_extension
        else:
            break
    return result_file_name


def get_folder_path_extracted_archives(file_path: str) -> str:
    extraction_result_folder_path = os.path.basename(
        file_path) + "_extracted"
    extraction_result_folder_path = define_result_file_or_folder_name(
        extraction_result_folder_path)
    folder_path_extracted_archives = f"{PATH_OF_EXTRACTED_ARCHIVES_FOLDER}{extraction_result_folder_path}"
    return folder_path_extracted_archives


def extract_archive(file_path: str) -> str:
    archive = zipfile.ZipFile(file_path, "r")
    folder_path_extracted_archives = get_folder_path_extracted_archives(
        file_path)
    archive.extractall(folder_path_extracted_archives)
    print(f"Archive extracted in {folder_path_extracted_archives}")
    archive.close()
    return folder_path_extracted_archives


def disasm_with_dex2jar(file_path: str, result_folder_name: str) -> None:
    file_name = define_result_file_or_folder_name(file_path)
    smali_result_folder_name = file_name + "_smali_files/"
    if "Windows" in platform.system():
        os.system(
            f"..\dex2jar-2.0\d2j-baksmali.bat {file_path} -o {PATH_OF_RESULTS_FOLDER}{result_folder_name}{smali_result_folder_name}")
    else:
        os.system(
            f"../dex2jar-2.0/d2j-baksmali.sh {file_path} -o {PATH_OF_RESULTS_FOLDER}{result_folder_name}{smali_result_folder_name}")


def define_md_options(file_path: str) -> Cs:
    file_content = open_file(file_path)
    file_type = magic.from_buffer(file_content)
    if "ARM" in file_type and "32-bit" in file_type:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        print("Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
    elif "ARM" in file_type and "64-bit" in file_type:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        print("Capstone start options: CS_ARCH_ARM64, CS_MODE_ARM")
    elif "Intel" in file_type and "16-bit" in file_type or "MS-DOS executable" in file_type or "NE for MS Windows" in file_type:
        md = Cs(CS_ARCH_X86, CS_MODE_16)
        print("Capstone start options: CS_ARCH_X86, CS_MODE_16")
    elif "Intel" in file_type and "32-bit" in file_type or "Intel 80386" in file_type or "x86-32" in file_type:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        print("Capstone start options: CS_ARCH_X86, CS_MODE_32")
    elif "Intel" in file_type and "64-bit" in file_type or "x86-64" in file_type:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        print("Capstone start options: CS_ARCH_X86, CS_MODE_64")
    else:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return md


def disasm_and_save_result(file_path: str, result_folder_name: str) -> None:
    file_content = open_file(file_path)

    # Setting disasm with capstone options on md
    md = define_md_options(file_path)
    first_disasm_mode = md.mode
    md.skipdata_setup = ("db", None, None)
    md.skipdata = True

    result_file_name = os.path.basename(file_path) + "_disasm.asm"
    result_file_name = define_result_file_or_folder_name(result_file_name)
    result_folder_path = f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_file_name}"

    # Disasm and saving result in {result_folder_path}
    with open(result_folder_path, "w") as result_file:
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
