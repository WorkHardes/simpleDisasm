import os

from config import RESULTS_FOLDER_PATH


def define_result_file_name(result_file_name: str) -> str:

    file_name = result_file_name[result_file_name.find(".")+1:]
    file_name = file_name[::-1]

    if result_file_name.find(".") != -1:
        file_extension = result_file_name[:result_file_name.find(".")]
        file_extension = file_extension[::-1]
    else:
        file_extension = ""

    result_file_name = file_name + "." + file_extension

    # Define file name. If this file name exists: file name += "file_name (копия name_counter).file_extension"
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
