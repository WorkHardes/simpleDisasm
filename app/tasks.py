import os
import magic

from celery import Celery

from config import RESULTS_FOLDER_PATH, BROKER_CONN_URI
from disasm import DisasmContext, DisasmArchiveStrategy, DisasmBinStrategy


BROKER_CONN_URI = "pyamqp://guest@localhost//"

celery = Celery('fileploader', broker=BROKER_CONN_URI, include=['tasks'])


@celery.task()
def disasm_file_task(file_path: str) -> None:
    # Define file name and type
    file_content = open(file_path, "rb").read()
    file_type = magic.from_buffer(file_content)
    result_folder_name = os.path.basename(file_path) + "_disasm"

    # Set copy in folder name if it exists
    name_counter = 0
    while True:
        if result_folder_name in os.listdir(f"{RESULTS_FOLDER_PATH}"):
            result_folder_name = result_folder_name.replace(
                f"_(копия {name_counter})", "")
            name_counter += 1
            result_folder_name += f"_(копия {name_counter})"
        else:
            result_folder_name += "/"
            break
    os.mkdir(f"{RESULTS_FOLDER_PATH}{result_folder_name}")

    if "Zip archive data" in file_type:
        context = DisasmContext(DisasmArchiveStrategy())
    else:
        context = DisasmContext(DisasmBinStrategy())
    context.choice_disasm_options(file_path, result_folder_name,
                                  file_type, file_content)
