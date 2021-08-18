from __future__ import annotations

import os
import pathlib
import shutil
import zipfile
import platform

import magic

from capstone import *
from abc import ABC, abstractmethod

from config import PATH_OF_RESULTS_FOLDER, PATH_OF_EXTRACTED_ARCHIVES_FOLDER, NAME_OF_EXTRACTED_ARCHIVES_FOLDER
from services import move_java_files


class DisasmContext():

    def __init__(self, disasm_strategy: DisasmStrategy) -> None:
        self._disasm_strategy = disasm_strategy

    @property
    def disasm_strategy(self) -> DisasmStrategy:
        return self._disasm_strategy

    @disasm_strategy.setter
    def disasm_strategy(self, disasm_strategy: DisasmStrategy) -> None:
        self._disasm_strategy = disasm_strategy

    def choice_disasm_strategy(self, file_path: str) -> None:
        self._disasm_strategy.disasm_file(file_path)


class DisasmStrategy(ABC):

    @abstractmethod
    def disasm_file(self, file_path: str) -> None:
        pass


class DisasmArchiveStrategy(DisasmStrategy):

    def extract_archive(self, file_path: str) -> str:
        archive = zipfile.ZipFile(file_path, "r")
        folder_path_extracted_archives = PATH_OF_EXTRACTED_ARCHIVES_FOLDER + \
            pathlib.Path(file_path).name + \
            "_extracted"
        archive.extractall(folder_path_extracted_archives)
        print(
            f"Archive {file_path} extracted in {folder_path_extracted_archives}")
        archive.close()
        return folder_path_extracted_archives

    def disasm_file(self, file_path: str) -> None:
        result_folder_name = pathlib.Path(file_path).name + "/"
        pathlib.Path(f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}").mkdir(parents=True,
                                                                            exist_ok=True)
        folder_path_extracted_archives = self.extract_archive(file_path)
        for root, dirs, files in os.walk(folder_path_extracted_archives):
            for extracted_file_path in files:
                extracted_file_path = root + "/" + extracted_file_path
                disasm_context = DisasmContext(DisasmBinFileStrategy())
                disasm_context.choice_disasm_strategy(extracted_file_path)
        move_java_files(file_path)


class DisasmBinFileStrategy(DisasmStrategy):

    def disasm_with_jadx(self, file_path: str) -> None:
        file_type = magic.from_file(file_path)
        print("file_path: ", file_path, "\nfile_type: ", file_type)

        result_folder_name_java_files = ""
        archive_name = file_path[file_path.find(NAME_OF_EXTRACTED_ARCHIVES_FOLDER)+19:
                                 file_path.find("_extracted")]
        if archive_name != "":
            result_folder_name = archive_name + "/"
            result_folder_name_java_files = "java_files/"
        else:
            result_folder_name = pathlib.Path(file_path).name
        if "Windows" in platform.system():
            os.system(
                rf"..\jadx-1.2.0\bin\jadx {file_path} -d {PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_folder_name_java_files}")
        else:
            os.system(
                rf"../jadx-1.2.0/bin/jadx {file_path} -d {PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_folder_name_java_files}")

    def disasm_with_dex2jar(self, file_path: str) -> None:
        result_folder_name_classes_dex = ""
        archive_name = file_path[file_path.find(NAME_OF_EXTRACTED_ARCHIVES_FOLDER)+19:
                                 file_path.find("_extracted")]
        if archive_name != "":
            result_folder_name = archive_name + "/"
            result_folder_name_classes_dex = "classes.dex/"
        else:
            result_folder_name = pathlib.Path(file_path).name
        if "Windows" in platform.system():
            os.system(
                rf"..\dex2jar-2.0\d2j-baksmali.bat {file_path} -o {PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_folder_name_classes_dex}")
        else:
            os.system(
                rf"../dex2jar-2.0/d2j-baksmali.sh {file_path} -o {PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_folder_name_classes_dex}")

    def define_md_options(self, file_path: str) -> Cs:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        file_type = magic.from_file(file_path)
        print("Filepath", file_path, "\nFiletype: ", file_type)
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

    def get_result_file_path(self, file_path: str) -> str:
        result_file_path = file_path[file_path.find(
            NAME_OF_EXTRACTED_ARCHIVES_FOLDER)+19:]
        result_file_path = result_file_path.replace("_extracted", "")
        if result_file_path == "":
            result_file_path = pathlib.Path(file_path).name
        result_file_path = PATH_OF_RESULTS_FOLDER + result_file_path + ".asm"
        return result_file_path

    def get_result_folder_path(self, result_file_path: str) -> str:
        result_folder_path = result_file_path[::-1]
        result_folder_path = result_folder_path[result_folder_path.find("/"):]
        result_folder_path = result_folder_path[::-1]
        return result_folder_path

    def get_file_content(self, file_path: str) -> str:
        try:
            file_obj = open(file_path, "rb")
            file_content = file_obj.read()
            file_obj.close()
            return file_content
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")

    def disasm_with_capstone(self, file_path: str) -> None:
        md = self.define_md_options(file_path)
        first_disasm_mode = md.mode

        result_file_path = self.get_result_file_path(file_path)
        result_folder_path = self.get_result_folder_path(result_file_path)
        pathlib.Path(result_folder_path).mkdir(parents=True, exist_ok=True)
        with open(result_file_path, "w") as result_file:
            file_content = self.get_file_content(file_path)
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
        print(f"Result of the disasm file in {result_file_path}", "\n")

    def disasm_file(self, file_path: str) -> None:
        file_type = magic.from_file(file_path)
        if "compiled Java class data" in file_type:
            self.disasm_with_jadx(file_path)
            move_java_files(file_path)
        elif "Dalvik dex" in file_type:
            self.disasm_with_dex2jar(file_path)
        elif "ELF" in file_type:
            self.disasm_with_capstone(file_path)
