import re

compare = dict()

compare["AWS"] = re.compile("AKIA[0-9A-Z]{16}")
compare["Facebook"] = re.compile("EAACEdEose0cBA[0-9A-Za-z]+")
compare["Github"] = re.compile("[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*")
compare["Telegram"] = re.compile("[0-9]+:AA[0-9A-Za-z\\-_]{33}")
compare["Square"] = re.compile("sq0atp-[0-9A-Za-z\\-_]{22}") #mobile 결제
compare["Twitter"] = re.compile("[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}")

compKey = compare.keys()