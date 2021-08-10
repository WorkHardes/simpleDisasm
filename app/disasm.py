from __future__ import annotations

import os
import pathlib
import zipfile
import magic
import platform

from capstone import *
from abc import ABC, abstractmethod

from config import PATH_OF_RESULTS_FOLDER, PATH_OF_EXTRACTED_ARCHIVES_FOLDER
from services import open_file, disasm_with_dex2jar, disasm_with_jadx, disasm_and_save_result


class DisasmContext():

    def __init__(self, disasm_strategy: DisasmStrategy) -> None:
        self._disasm_strategy = disasm_strategy

    @property
    def disasm_strategy(self) -> DisasmStrategy:
        return self._disasm_strategy

    @disasm_strategy.setter
    def disasm_strategy(self, disasm_strategy: DisasmStrategy) -> None:
        self._disasm_strategy = disasm_strategy

    def choice_disasm_options(self, file_path: str, result_folder_name: str = None) -> None:
        self._disasm_strategy.disasm_file(file_path, result_folder_name)


class DisasmStrategy(ABC):

    @abstractmethod
    def disasm_file(self, file_path: str, result_folder_name: str = None) -> None:
        pass


class DisasmArchiveStrategy(DisasmStrategy):

    def get_folder_path_extracted_archives(self, file_path: str) -> str:
        folder_path_extracted_archives = pathlib.Path(file_path).name
        folder_path_extracted_archives += "_extracted"
        folder_path_extracted_archives = f"{PATH_OF_EXTRACTED_ARCHIVES_FOLDER}{folder_path_extracted_archives}"
        return folder_path_extracted_archives

    def extract_archive(self, file_path: str) -> str:
        archive = zipfile.ZipFile(file_path, "r")
        folder_path_extracted_archives = self.get_folder_path_extracted_archives(
            file_path)
        archive.extractall(folder_path_extracted_archives)
        print(f"Archive extracted in {folder_path_extracted_archives}")
        archive.close()
        return folder_path_extracted_archives

    def get_executable_file_paths_list(self, file_path: str, result_folder_name: str) -> list:
        folder_path_extracted_archives = self.extract_archive(file_path)
        executable_file_paths_list = []
        for root, dirs, files in os.walk(folder_path_extracted_archives):
            for extracted_file in files:
                extracted_file = root + "/" + extracted_file
                file_content = open_file(extracted_file)
                file_type = magic.from_buffer(file_content)
                if "ELF" in file_type:
                    executable_file_paths_list.append(extracted_file)
                elif "compiled Java class data" in file_type:
                    disasm_with_jadx(file_path, result_folder_name)
        return executable_file_paths_list

    def disasm_executable_files(self, executable_file_paths_list: list, result_folder_name: str) -> None:
        for file_path in executable_file_paths_list:
            file_content = open_file(file_path)
            if file_content != None:
                file_type = magic.from_buffer(file_content)
                print("Filepath", file_path, "\nFiletype: ", file_type,
                      "Capstone start options: CS_ARCH_ARM, CS_MODE_ARM")
                disasm_and_save_result(file_path, result_folder_name)

    def disasm_file(self, file_path: str, result_folder_name: str = None) -> None:
        pathlib.Path(f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}").mkdir(parents=True,
                                                                            exist_ok=True)
        # Disasm .dex files to .smali
        disasm_with_dex2jar(file_path, result_folder_name)

        executable_file_paths_list = self.get_executable_file_paths_list(file_path,
                                                                         result_folder_name)
        file_full_name = pathlib.Path(file_path).name
        if len(executable_file_paths_list) != 0:
            result_folder_name += "/"
            asm_result_folder_name = file_full_name + "_asm_files/"
            pathlib.Path(f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}{asm_result_folder_name}").mkdir(parents=True,
                                                                                                        exist_ok=True)
            result_folder_name += asm_result_folder_name
            self.disasm_executable_files(executable_file_paths_list,
                                         result_folder_name)


class DisasmBinFileStrategy(DisasmStrategy):

    def disasm_file(self, file_path: str, result_folder_name: str = None) -> None:
        file_content = open_file(file_path)
        file_type = magic.from_buffer(file_content)
        if "compiled Java class data" in file_type:
            disasm_with_jadx(file_path)
        elif "Dalvik dex" in file_type:
            disasm_with_dex2jar(file_path)
        else:
            disasm_and_save_result(file_path)
