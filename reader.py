import csv

def read_log_file(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        data = [line for line in reader]
        return data
