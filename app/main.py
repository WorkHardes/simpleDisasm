from tasks import file_disasm_task
from services import open_file


def main() -> None:
    while True:
        file_path = "../files/5.apk"
        if open_file(file_path) != None:
            break

    file_disasm_task.delay(file_path)


if __name__ == "__main__":
    main()
