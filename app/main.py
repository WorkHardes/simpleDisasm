from tasks import file_disasm_task
from services import open_file


def main() -> None:
    while True:
        # file_path = str(input("Inputh file or archive path: "))
        file_path = "../files/7.jar"
        if open_file(file_path) != None:
            break

    file_disasm_task.delay(file_path)


if __name__ == "__main__":
    main()
