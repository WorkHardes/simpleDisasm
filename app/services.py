def open_file(file_path: str) -> str:
    try:
        file_content = open(file_path, "rb").read()
        return file_content
    except FileNotFoundError:
        print(f"Error! File {file_path} doesn't exists!")
