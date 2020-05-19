import sys

def remove_duplicates(raw_file):
	uniques = set(raw_file.readlines())
	for x in uniques:
		print(x, end = '')
	return uniques


f = open(sys.argv[1])
uniques = remove_duplicates(f)
f.close()
