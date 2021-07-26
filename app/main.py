import os
import zipfile
import magic

from capstone import *

from config import RESULTS_FOLDER_PATH
from services import disasm_archive, disasm_bin_file


def main():
    # Open file
    while True:
        file_path = "../files/1.jar"
        # file_path = str(input("Inputh file or archive path: "))
        try:
            file_content = open(file_path, "rb").read()
            break
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")

    # Define file name and type
    file_type = magic.from_buffer(file_content)
    result_folder_name = os.path.basename(file_path) + " disasm/"
    os.mkdir(f"{RESULTS_FOLDER_PATH}{result_folder_name}")

    if "Zip archive data" in file_type:
        disasm_archive(file_path, result_folder_name)
    else:
        disasm_bin_file(file_path, file_type, file_content, result_folder_name)


if __name__ == "__main__":
    main()
