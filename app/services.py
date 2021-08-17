import os
import pathlib
import shutil


from config import PATH_OF_RESULTS_FOLDER


def open_file(file_path: str) -> str:
    try:
        file_content = open(file_path, "rb").read()
        return file_content
    except FileNotFoundError:
        print(f"Error! File {file_path} doesn't exists!")


def move_java_files(file_path: str) -> None:
    file_name = pathlib.Path(file_path).name
    path_java_files = f"{PATH_OF_RESULTS_FOLDER}{file_name}"
    if pathlib.Path(f"{path_java_files}/java_files/sources/").exists() is True:
        path_java_files += "/java_files/"
    elif pathlib.Path(f"{path_java_files}/sources/").exists() is True:
        path_java_files += "/sources/"
    else:
        return

    for root, dirs, files in os.walk(f"{path_java_files}"):
        for java_file in files:
            result_folder_path = root.replace("/java_files", "")
            result_folder_path = result_folder_path.replace("/sources", "")
            result_folder_path = result_folder_path.replace(java_file, "")
            pathlib.Path(result_folder_path).mkdir(parents=True,
                                                   exist_ok=True)
            shutil.move(f"{root}/{java_file}",
                        result_folder_path)
    shutil.rmtree(path_java_files)
