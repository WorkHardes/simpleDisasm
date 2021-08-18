import magic

from celery import Celery

from config import BROKER_CONN_URI
from disasm import DisasmContext, DisasmArchiveStrategy, DisasmBinFileStrategy


# BROKER_CONN_URI = "pyamqp://guest@localhost//"
celery_app = Celery('fileploader', broker=BROKER_CONN_URI)


@celery_app.task()
def file_disasm_task(file_path: str) -> None:
    file_type = magic.from_file(file_path)
    if "Zip archive data" in file_type:
        disasm_context = DisasmContext(DisasmArchiveStrategy())
    else:
        disasm_context = DisasmContext(DisasmBinFileStrategy())
    disasm_context.choice_disasm_strategy(file_path)
