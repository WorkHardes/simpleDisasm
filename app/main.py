from tasks import file_disasm_task
from services import open_file


if __name__ == "__main__":
    while True:
        # file_path = str(input("Inputh file or archive path: "))
        file_path = "../files/5.apk"
        if open_file(file_path) != None:
            break

    file_disasm_task.delay(file_path)
