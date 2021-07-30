from __future__ import annotations

import os
import pathlib
import zipfile
import magic

from capstone import *
from capstone.arm import *
from abc import ABC, abstractmethod
from typing import List

from config import RESULTS_FOLDER_PATH, RESULT_EXTRACTED_ARCHIVE_PATH


class DisasmContext():

    def __init__(self, strategy: DisasmStrategy) -> None:
        self._strategy = strategy

    @property
    def strategy(self) -> DisasmStrategy:
        return self._strategy

    @strategy.setter
    def strategy(self, strategy: DisasmStrategy) -> None:
        self._strategy = strategy

    def choice_disasm_options(self, file_path: str, result_folder_name: str, file_type: str = None, file_content=None) -> None:
        self._strategy.disasm_file(file_path, result_folder_name,
                                   file_type, file_content)


class DisasmStrategy(ABC):

    @abstractmethod
    def disasm_file(self, file_path: str, result_folder_name: str, file_type: str = None, file_content=None) -> None:
        pass

    def define_result_file_name(self, result_file_name: str) -> str:
        file_name = result_file_name[result_file_name.find(".")+1:]
        file_name = file_name[::-1]

        if result_file_name.find(".") != -1:
            file_extension = result_file_name[:result_file_name.find(".")]
            file_extension = file_extension[::-1]
        else:
            file_extension = ""

        result_file_name = file_name + "." + file_extension

        # Define file name. If this file name exists: {file_name} += "{file_name} (копия {name_counter}).{file_extension}"
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

    def extract_archive(self, file_path: str) -> str:
        archive = zipfile.ZipFile(file_path, "r")

        result_folder_path = os.path.basename(file_path) + " extracted"
        result_folder_path = self.define_result_file_name(
            result_folder_path[::-1])

        result_of_extraction_path = f"{RESULT_EXTRACTED_ARCHIVE_PATH}{result_folder_path}"
        archive.extractall(result_of_extraction_path)

        print(f"Archive extracted in {result_of_extraction_path}")

        archive.close()
        return result_of_extraction_path

    def disasm_and_save_result(self, md, result_folder_name: str, result_file_name: str, file_content) -> None:
        # Set capstone options on md
        first_mode = md.mode
        md.skipdata_setup = ("db", None, None)
        md.skipdata = True

        result_folder_path = f"{RESULTS_FOLDER_PATH}{result_folder_name}{result_file_name}"

        # Disasm and save result in {result_folder_path}
        with open(result_folder_path, "w") as result_file:

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
            f"Result of the disasm file in {RESULTS_FOLDER_PATH}{result_file_name}", "\n")


class DisasmArchiveStrategy(DisasmStrategy):

    def disasm_file(self, file_path: str, result_folder_name: str, file_type: str = None, file_content=None) -> None:
        result_of_extraction_path = self.extract_archive(file_path)
        executable_files_list = []

        # Create list of path of .class files
        for root, dirs, files in os.walk(result_of_extraction_path):
            for file in files:
                file = root + "/" + file
                file_content = open(file, "rb").read()
                file_type = magic.from_buffer(file_content)
                if "compiled Java class data" in file_type or "Dalvik dex file" in file_type or "ELF" in file_type:
                    executable_files_list.append(os.path.join(root, file))

        # Disasm all classes in extracted jar file
        for file_path in executable_files_list:
            try:
                file_content = open(file_path, "rb").read()
            except FileNotFoundError:
                print(f"Error! File {file_path} doesn't exists!")

            file_type = magic.from_buffer(file_content)
            result_file_name = os.path.basename(file_path) + " disasm.txt"
            result_file_name = self.define_result_file_name(
                result_file_name[::-1])

            print("Filetype: ", file_type)

            # Disassembly file and write result in folder ..results/
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
            self.disasm_and_save_result(md, result_folder_name,
                                        result_file_name, file_content)


class DisasmBinStrategy(DisasmStrategy):

    def disasm_file(self, file_path: str, result_folder_name: str, file_type: str = None, file_content=None) -> None:
        result_file_name = os.path.basename(file_path) + " disasm.txt"
        result_file_name = self.define_result_file_name(result_file_name[::-1])

        # Disassembly file and write result in folder ..results/
        if "ARM" in file_type and "32-bit" in file_type or "compiled Java class data" in file_type:
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
            self.disasm_and_save_result(md, result_folder_name,
                                        result_file_name, file_content)

        elif "ARM" in file_type and "64-bit" in file_type:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM64, CS_MODE_ARM")
            self.disasm_and_save_result(md, result_folder_name,
                                        result_file_name, file_content)

        elif "Intel" in file_type and "16-bit" in file_type or "MS-DOS executable" in file_type or "NE for MS Windows" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_16)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_16")
            self.disasm_and_save_result(md, result_folder_name,
                                        result_file_name, file_content)

        elif "Intel" in file_type and "32-bit" in file_type or "Intel 80386" in file_type or "x86-32" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_32")
            self.disasm_and_save_result(md, result_folder_name,
                                        result_file_name, file_content)

        elif "Intel" in file_type and "64-bit" in file_type or "x86-64" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_64")
            self.disasm_and_save_result(md, result_folder_name,
                                        result_file_name, file_content)


if __name__ == "__main__":
    # Open file
    while True:
        # file_path = str(input("Inputh file or archive path: "))
        file_path = "../files/5.apk"
        try:
            file_content = open(file_path, "rb").read()
            break
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")

    # Define file name and type
    file_type = magic.from_buffer(file_content)
    result_folder_name = os.path.basename(file_path) + " disasm/"
    # result_folder_name = define_result_file_name()
    os.mkdir(f"{RESULTS_FOLDER_PATH}{result_folder_name}")

    if "Zip archive data" in file_type:
        context = DisasmContext(DisasmArchiveStrategy())
    else:
        context = DisasmContext(DisasmBinStrategy())

    context.choice_disasm_options(file_path, result_folder_name,
                                  file_type, file_content)
