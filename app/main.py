# import os

from tasks import disasm_file_task


if __name__ == "__main__":
    # os.system("dir")

    # Open file
    while True:
        # file_path = str(input("Inputh file or archive path: "))
        file_path = "../files/1.jar"
        try:
            file_content = open(file_path, "rb").read()
            break
        except FileNotFoundError:
            print(f"Error! File {file_path} doesn't exists!")

    disasm_file_task(file_path)
