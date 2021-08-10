import pathlib
import magic

from celery import Celery

from config import PATH_OF_RESULTS_FOLDER, BROKER_CONN_URI
from disasm import DisasmContext, DisasmArchiveStrategy, DisasmBinFileStrategy
from services import open_file


# BROKER_CONN_URI = "pyamqp://guest@localhost//"
celery_app = Celery('fileploader', broker=BROKER_CONN_URI)


@celery_app.task()
def file_disasm_task(file_path: str) -> None:
    file_content = open_file(file_path)
    file_type = magic.from_buffer(file_content)
    if "Zip archive data" in file_type:
        result_folder_name = pathlib.Path(file_path).name
        disasm_context = DisasmContext(DisasmArchiveStrategy())
    else:
        result_folder_name = None
        disasm_context = DisasmContext(DisasmBinFileStrategy())
    disasm_context.choice_disasm_options(file_path, result_folder_name)
