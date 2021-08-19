from tasks import file_disasm_task


def main() -> None:
    file_path = "../files/3.so"
    try:
        file_obj = open(file_path, "rb")
        file_obj.close()
    except FileNotFoundError:
        print(f"Error! No such file: {file_path}")

    file_disasm_task.delay(file_path)


if __name__ == "__main__":
    main()
