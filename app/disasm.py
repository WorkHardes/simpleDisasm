from __future__ import annotations

import os
import shutil
import platform
import magic

from abc import ABC, abstractmethod
from pathlib import Path
from zipfile import ZipFile

from capstone import *

from config import PATH_OF_RESULTS_FOLDER, PATH_OF_EXTRACTED_ARCHIVES_FOLDER, NAME_OF_EXTRACTED_ARCHIVES_FOLDER


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


class FileServices():

    def get_java_files_path(self, file_path: str) -> str:
        file_name = Path(file_path).name
        java_files_path = PATH_OF_RESULTS_FOLDER + file_name
        if Path(f"{java_files_path}/java_files/sources/").exists() is True:
            java_files_path += "/java_files/"
        elif Path(f"{java_files_path}/sources/").exists() is True:
            java_files_path += "/sources/"
        else:
            return None
        return java_files_path

    def move_java_files(self, file_path: str) -> None:
        java_files_path = self.get_java_files_path(file_path)
        if java_files_path is None:
            return
        for root, dirs, files in os.walk(java_files_path):
            for java_file in files:
                result_folder_path = root.replace("/java_files", "")
                result_folder_path = result_folder_path.replace("/sources", "")
                result_folder_path = result_folder_path.replace(java_file, "")
                Path(result_folder_path).mkdir(parents=True,
                                               exist_ok=True)
                shutil.move(f"{root}/{java_file}",
                            result_folder_path)
        shutil.rmtree(java_files_path)


class DisasmArchiveStrategy(DisasmStrategy, FileServices):

    def extract_archive(self, file_path: str) -> str:
        exctracted_archive_name = Path(file_path).name + "_extracted"
        extracted_archives_path = Path().joinpath(PATH_OF_EXTRACTED_ARCHIVES_FOLDER,
                                                  exctracted_archive_name)
        archive = ZipFile(file_path, "r")
        archive.extractall(extracted_archives_path)
        print(f"Archive {file_path} extracted in {extracted_archives_path}")
        archive.close()
        return extracted_archives_path

    def disasm_file(self, file_path: str) -> None:
        result_folder_name = Path(file_path).name
        Path(f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}").mkdir(parents=True,
                                                                    exist_ok=True)

        extracted_archives_path = self.extract_archive(file_path)
        for root, dirs, files in os.walk(extracted_archives_path):
            for extracted_file_path in files:
                extracted_file_path = root + "/" + extracted_file_path
                disasm_context = DisasmContext(DisasmBinFileStrategy())
                disasm_context.choice_disasm_strategy(extracted_file_path)
        self.move_java_files(file_path)


class CapstoneDisassembler():

    def get_md_arm_options(self, file_type: str, md: Cs) -> Cs:
        if "32-bit" in file_type:
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
        elif"64-bit" in file_type:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            print("Capstone start options: CS_ARCH_ARM64, CS_MODE_ARM")
        return md

    def get_md_intel_options(self, file_type: str, md: Cs) -> Cs:
        if "16-bit" in file_type or "MS-DOS executable" in file_type or "NE for MS Windows" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_16)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_16")
        elif "32-bit" in file_type or "Intel 80386" in file_type or "x86-32" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_32")
        elif "64-bit" in file_type or "x86-64" in file_type:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            print("Capstone start options: CS_ARCH_X86, CS_MODE_64")
        return md

    def get_md_options(self, file_path: str) -> Cs:
        file_type = magic.from_file(file_path)
        print("Filepath", file_path, "\nFiletype: ", file_type)
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        if "ARM" in file_type:
            md = self.get_md_arm_options(file_type, md)
        if "Intel" in file_type:
            md = self.get_md_intel_options(file_type, md)
        md.skipdata_setup = ("db", None, None)
        md.skipdata = True
        return md

    def get_result_file_path(self, file_path: str) -> str:
        if file_path.find(NAME_OF_EXTRACTED_ARCHIVES_FOLDER) != -1:
            result_file_path = file_path[file_path.find(NAME_OF_EXTRACTED_ARCHIVES_FOLDER) +
                                         len(NAME_OF_EXTRACTED_ARCHIVES_FOLDER)+1:]
            result_file_path = result_file_path.replace("_extracted", "")
        else:
            result_file_path = None

        if result_file_path is None:
            result_file_path = Path(file_path).name
        result_file_path = PATH_OF_RESULTS_FOLDER + result_file_path + ".asm"
        return result_file_path

    def get_file_content(self, file_path: str) -> bytes:
        try:
            file_obj = open(file_path, "rb")
            file_content = file_obj.read()
            file_obj.close()
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")
        return file_content

    def disasm_with_capstone(self, file_path: str) -> None:
        md = self.get_md_options(file_path)
        first_disasm_mode = md.mode

        result_file_path = self.get_result_file_path(file_path)
        result_folder_path = Path(Path(result_file_path).parent)
        Path(result_folder_path).mkdir(parents=True, exist_ok=True)
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


class DisasmBinFileStrategy(DisasmStrategy, FileServices):

    def get_result_file_path(self, file_path: str) -> str:
        if file_path.find(NAME_OF_EXTRACTED_ARCHIVES_FOLDER) != -1:
            archive_name = file_path[file_path.find(NAME_OF_EXTRACTED_ARCHIVES_FOLDER) +
                                     len(NAME_OF_EXTRACTED_ARCHIVES_FOLDER)+1:
                                     file_path.find("_extracted")]
        else:
            archive_name = None

        if archive_name is not None:
            result_folder_name = archive_name + "/"
            file_type = magic.from_file(file_path)
            if "compiled Java class data" in file_type:
                result_folder_name += "java_files/"
            elif "Dalvik dex" in file_type:
                result_folder_name += "classes.dex/"
        else:
            result_folder_name = Path(file_path).name
        result_file_path = PATH_OF_RESULTS_FOLDER + result_folder_name
        return result_file_path

    def disasm_with_jadx(self, file_path: str) -> None:
        result_file_path = self.get_result_file_path(file_path)
        if "Windows" in platform.system():
            os.system(
                rf"..\jadx-1.2.0\bin\jadx {file_path} -d {result_file_path}")
        else:
            os.system(
                rf"../jadx-1.2.0/bin/jadx {file_path} -d {result_file_path}")

    def disasm_with_dex2jar(self, file_path: str) -> None:
        result_file_path = self.get_result_file_path(file_path)
        if "Windows" in platform.system():
            os.system(
                rf"..\dex2jar-2.0\d2j-baksmali.bat {file_path} -o {result_file_path}")
        else:
            os.system(
                rf"../dex2jar-2.0/d2j-baksmali.sh {file_path} -o {result_file_path}")

    def disasm_file(self, file_path: str) -> None:
        file_type = magic.from_file(file_path)
        if "compiled Java class data" in file_type:
            self.disasm_with_jadx(file_path)
            self.move_java_files(file_path)
        elif "Dalvik dex" in file_type:
            self.disasm_with_dex2jar(file_path)
        elif "ELF" in file_type:
            CapstoneDisassembler().disasm_with_capstone(file_path)
