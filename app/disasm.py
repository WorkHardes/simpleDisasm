from __future__ import annotations

import os
import zipfile
import magic

from capstone import *
from abc import ABC, abstractmethod

from config import PATH_OF_RESULTS_FOLDER, PATH_OF_EXTRACTED_ARCHIVES_FOLDER


class DisasmContext():

    def __init__(self, disasm_strategy: DisasmStrategy) -> None:
        self._disasm_strategy = disasm_strategy

    @property
    def disasm_strategy(self) -> DisasmStrategy:
        return self._disasm_strategy

    @disasm_strategy.setter
    def disasm_strategy(self, disasm_strategy: DisasmStrategy) -> None:
        self._disasm_strategy = disasm_strategy

    def choice_disasm_options(self, file_path: str, result_folder_name: str) -> None:
        self._disasm_strategy.disasm_file(file_path, result_folder_name)


class DisasmStrategy(ABC):

    @abstractmethod
    def disasm_file(self, file_path: str, result_folder_name: str) -> None:
        pass

    def get_file_name(self, file_full_name: str) -> str:
        file_full_name = file_full_name[::-1]
        file_name = file_full_name[file_full_name.find(".")+1:]
        file_name = file_name[::-1]
        return file_name

    def get_file_extension(self, file_full_name: str) -> str:
        if file_full_name.find(".") != -1:
            file_extension = file_full_name[:file_full_name.find(".")]
            file_extension = file_extension[::-1]
        else:
            file_extension = ""
        return file_extension

    def define_result_file_name(self, file_full_name: str) -> str:
        file_name = self.get_file_name(file_full_name)
        file_extension = self.get_file_extension(file_full_name)
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

    def get_folder_path_extracted_archives(self, file_path: str) -> str:
        extraction_result_folder_path = os.path.basename(
            file_path) + "_extracted"
        extraction_result_folder_path = self.define_result_file_name(
            extraction_result_folder_path)
        folder_path_extracted_archives = f"{PATH_OF_EXTRACTED_ARCHIVES_FOLDER}{extraction_result_folder_path}"
        return folder_path_extracted_archives

    def extract_archive(self, file_path: str) -> str:
        archive = zipfile.ZipFile(file_path, "r")
        folder_path_extracted_archives = self.get_folder_path_extracted_archives(
            file_path)
        archive.extractall(folder_path_extracted_archives)
        print(f"Archive extracted in {folder_path_extracted_archives}")
        archive.close()
        return folder_path_extracted_archives

    def disasm_and_save_result(self, md: Cs, file_path: str, result_folder_name: str, result_file_name: str) -> None:
        try:
            file_content = open(file_path, "rb").read()
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")
        # Setting disasm with capstone options on md
        first_disasm_mode = md.mode
        md.skipdata_setup = ("db", None, None)
        md.skipdata = True

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

                result_file.write("0x{: <5} {: <8} {: <8}\n".format(
                    address, mnemonic, op_str))

        print(f"Result of the disasm file in {result_folder_path}", "\n")


class DisasmArchiveStrategy(DisasmStrategy):

    def disasm_file(self, file_path: str, result_folder_name: str) -> None:
        try:
            file_content = open(file_path, "rb").read()
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")
        file_type = magic.from_buffer(file_content)
        file_name = file_path[::-1]
        file_name = file_name[file_name.find("/")-1::-1]
        smali_result_folder_name = file_name + "_smali_files"

        # Disasm .dex files to .smali files using dex2jar
        os.system(
            f"../dex2jar-2.0/d2j-baksmali.sh {file_path} -o {PATH_OF_RESULTS_FOLDER}{result_folder_name}{smali_result_folder_name}")

        result_of_extraction_folder_path = self.extract_archive(file_path)
        executable_files_list = []

        # Creating list of path of .class files
        for root, dirs, files in os.walk(result_of_extraction_folder_path):
            for file_path in files:
                file_path = root + "/" + file_path
                try:
                    file_content = open(file_path, "rb").read()
                except FileNotFoundError:
                    print(f"Error! File {file_path} doesn't exists!")
                file_type = magic.from_buffer(file_content)

                if "ELF" in file_type:
                    executable_files_list.append(os.path.join(file_path))
                # Disasm .class files with jadx
                elif "compiled Java class data" in file_type:
                    print("file_path: ", file_path, "\nfile_type: ", file_type)
                    if "_java_files" not in result_folder_name:
                        result_folder_name_java_files = file_name + "_java_files"
                    os.system(
                        f"../jadx-1.2.0/bin/jadx {file_path} -d {PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_folder_name_java_files}")

        if len(executable_files_list) != 0:
            asm_result_folder_name = file_name + "_asm_files/"
            result_folder_name += asm_result_folder_name
            res = os.mkdir(f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}")

        # Checking if a file exists
        for file_path in executable_files_list:
            try:
                file_content = open(file_path, "rb").read()
            except FileNotFoundError:
                print(f"Error! File {file_path} doesn't exists!")
                continue

            file_type = magic.from_buffer(file_content)
            print("Filepath", file_path, "\nFiletype: ", file_type)

            result_file_name = os.path.basename(file_path) + "_disasm.asm"
            result_file_name = self.define_result_file_name(result_file_name)

            # Disasm file and write result in folder ../results/
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
            self.disasm_and_save_result(md, file_path,
                                        result_folder_name, result_file_name)


class DisasmBinFileStrategy(DisasmStrategy):

    def disasm_file(self, file_path: str, result_folder_name: str) -> None:
        try:
            file_content = open(file_path, "rb").read()
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")
        file_type = magic.from_buffer(file_content)
        result_file_name = os.path.basename(file_path) + "_disasm.asm"
        result_file_name = self.define_result_file_name(result_file_name)

        # Disassembly file and write result in folder ..results/
        if "compiled Java class data" in file_type:
            if "_java_files" not in result_folder_name:
                result_folder_name += "_java_files"
            os.system(
                f"../jadx-1.2.0/bin/jadx {file_path} -d {PATH_OF_RESULTS_FOLDER}{result_folder_name}")

        if "ARM" in file_type and "32-bit" in file_type:
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
            self.disasm_and_save_result(md, file_path,
                                        result_folder_name, result_file_name)

        elif "ARM" in file_type and "64-bit" in file_type:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM64, CS_MODE_ARM")
            self.disasm_and_save_result(md, file_path,
                                        result_folder_name, result_file_name)

        elif "Intel" in file_type and "16-bit" in file_type or "MS-DOS executable" in file_type or "NE for MS Windows" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_16)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_16")
            self.disasm_and_save_result(md, file_path,
                                        result_folder_name, result_file_name)

        elif "Intel" in file_type and "32-bit" in file_type or "Intel 80386" in file_type or "x86-32" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_32")
            self.disasm_and_save_result(md, file_path,
                                        result_folder_name, result_file_name)

        elif "Intel" in file_type and "64-bit" in file_type or "x86-64" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_64")
            self.disasm_and_save_result(md, file_path,
                                        result_folder_name, result_file_name)
