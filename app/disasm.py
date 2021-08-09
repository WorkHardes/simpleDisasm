from __future__ import annotations

import os
import zipfile
import magic
import platform

from capstone import *
from abc import ABC, abstractmethod

from config import PATH_OF_RESULTS_FOLDER, PATH_OF_EXTRACTED_ARCHIVES_FOLDER
from services import open_file, define_result_file_or_folder_name, extract_archive, disasm_with_dex2jar, disasm_and_save_result


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


class DisasmArchiveStrategy(DisasmStrategy):

    def disasm_file(self, file_path: str, result_folder_name: str) -> None:
        file_content = open_file(file_path)
        file_type = magic.from_buffer(file_content)

        # Disasm .dex files to .smali
        disasm_with_dex2jar(file_path, result_folder_name)

        file_full_name = define_result_file_or_folder_name(file_path)
        result_of_extraction_folder_path = extract_archive(file_path)
        result_folder_name_java_files = file_full_name + "_java_files/"
        executable_file_paths_list = []
        for root, dirs, files in os.walk(result_of_extraction_folder_path):
            for file_path in files:
                file_path = root + "/" + file_path
                file_content = open_file(file_path)
                file_type = magic.from_buffer(file_content)
                if "ELF" in file_type:
                    executable_file_paths_list.append(os.path.join(file_path))
                elif "compiled Java class data" in file_type:
                    print("file_path: ", file_path, "\nfile_type: ", file_type)
                    os.system(
                        f"../jadx-1.2.0/bin/jadx {file_path} -d {PATH_OF_RESULTS_FOLDER}{result_folder_name}{result_folder_name_java_files}")

        if len(executable_file_paths_list) != 0:
            asm_result_folder_name = file_full_name + "_asm_files/"
            res = os.mkdir(
                f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}{asm_result_folder_name}")
            result_folder_name += asm_result_folder_name
            for file_path in executable_file_paths_list:
                file_content = open_file(file_path)
                if file_content != None:
                    file_type = magic.from_buffer(file_content)
                    print("Filepath", file_path, "\nFiletype: ", file_type,
                          "Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
                    disasm_and_save_result(file_path, result_folder_name)


class DisasmBinFileStrategy(DisasmStrategy):

    def disasm_file(self, file_path: str, result_folder_name: str) -> None:
        file_content = open_file(file_path)
        file_type = magic.from_buffer(file_content)
        if "compiled Java class data" in file_type:
            if "_java_files" not in result_folder_name:
                result_folder_name += "_java_files/"
            os.system(
                f"../jadx-1.2.0/bin/jadx {file_path} -d {PATH_OF_RESULTS_FOLDER}{result_folder_name}")
        elif "Dalvik dex" in file_type:
            disasm_with_dex2jar(file_path, result_folder_name)
        else:
            disasm_and_save_result(file_path, result_folder_name)
