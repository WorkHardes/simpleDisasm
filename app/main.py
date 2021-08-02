from tasks import disasm_file_task


if __name__ == "__main__":
    # Open file
    while True:
        # file_path = str(input("Inputh file or archive path: "))
        file_path = "../files/5.apk"
        try:
            file_content = open(file_path, "rb").read()
            break
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")

    disasm_file_task(file_path)
