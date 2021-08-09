import os
import magic

from celery import Celery

from config import PATH_OF_RESULTS_FOLDER, BROKER_CONN_URI
from services import define_result_file_or_folder_name
from disasm import DisasmContext, DisasmArchiveStrategy, DisasmBinFileStrategy


# BROKER_CONN_URI = "pyamqp://guest@localhost//"
celery_app = Celery('fileploader', broker=BROKER_CONN_URI)


@celery_app.task()
def file_disasm_task(file_path: str) -> None:
    result_folder_name = os.path.basename(file_path) + "_disasm"
    result_folder_name = define_result_file_or_folder_name(
        result_folder_name) + "/"
    os.mkdir(f"{PATH_OF_RESULTS_FOLDER}{result_folder_name}")

    file_content = open(file_path, "rb").read()
    file_type = magic.from_buffer(file_content)
    if "Zip archive data" in file_type:
        disasm_context = DisasmContext(DisasmArchiveStrategy())
    else:
        disasm_context = DisasmContext(DisasmBinFileStrategy())
    disasm_context.choice_disasm_options(file_path, result_folder_name)
