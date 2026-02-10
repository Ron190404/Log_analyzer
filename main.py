from reader import read_log_file

donnees = read_log_file("network_traffic.log")
print(donnees[ :5])