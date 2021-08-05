import os
import magic

from celery import Celery

from config import PATH_OF_RESULTS_FOLDER, BROKER_CONN_URI
from disasm import DisasmContext, DisasmArchiveStrategy, DisasmBinFileStrategy


# BROKER_CONN_URI = "pyamqp://guest@localhost//"
celery = Celery('fileploader', broker=BROKER_CONN_URI)


@celery.task()
def file_disasm_task(file_path: str) -> None:
    # Define file type
    file_content = open(file_path, "rb").read()
    file_type = magic.from_buffer(file_content)
    result_folder_name = os.path.basename(file_path) + "_disasm"

    # Define file name by setting (копия X) in folder name if it exists
    copy_number_counter = 0
    while True:
        if result_folder_name in os.listdir(f"{PATH_OF_RESULTS_FOLDER}"):
            result_folder_name = result_folder_name.replace(f"_(копия {copy_number_counter})",
                                                            "")
            copy_number_counter += 1
            result_folder_name += f"_(копия {copy_number_counter})"
        else:
            result_folder_name += "/"
            break

    os.mkdir(f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}")

    # Choosing a strategy for disasm an archive and a binary file
    if "Zip archive data" in file_type:
        disasm_context = DisasmContext(DisasmArchiveStrategy())
    else:
        disasm_context = DisasmContext(DisasmBinFileStrategy())
    disasm_context.choice_disasm_options(file_path, result_folder_name)
