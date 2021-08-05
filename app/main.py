from tasks import file_disasm_task


if __name__ == "__main__":
    # Open file
    while True:
        # file_path = str(input("Inputh file or archive path: "))
        file_path = "../files/5.apk"
        try:
            open(file_path, "rb").read()
            break
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")

    # Starting a task for file disasm
    file_disasm_task.delay(file_path)
