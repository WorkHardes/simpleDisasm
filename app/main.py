from tasks import file_disasm_task


def main() -> None:
    while True:
        # file_path = str(input("Inputh file or archive path: "))
        file_path = "../files/5.apk"
        with open(file_path, "rb") as file_obj:
            if file_obj != None:
                break
            file_obj.close()

    file_disasm_task.delay(file_path)


if __name__ == "__main__":
    main()
