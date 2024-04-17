import csv
import re
import os

# Mapping from library name to years available.
libraries_c = {
	'openssl': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'nss': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'gnutls': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'libressl': ['2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'boringssl': ['2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'botan': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'libgcrypt': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'wolfssl': ['2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'matrixssl': ['2016', '2017', '2018', '2019', '2020', '2021'],
	'cryptopp': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'nettle': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'mbedtls': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'libtomcrypt': ['2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'relic': ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022']
}

libraries_java = {
	'bouncy_castle': ['2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
}

libraries_python = {
	'pycrypto': ['2010', '2011', '2012', '2013'],
	'python_cryptography': ['2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
	'pycryptodome': ['2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
}

libraries_rust = {
	'sodium_oxide': ['2018', '2019', '2020', '2021'],
	'rustls': ['2017', '2018', '2019', '2020', '2021', '2022'],
	'orion': ['2018', '2019', '2020', '2021', '2022'],
}

libraries_go = {
	'golang': ['2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022']
}

def make_dir(dir_path):
	if not os.path.exists(dir_path):
		os.makedirs(dir_path)

def run_lizard(lib, year, language):
	print(f'Running lizard for: {lib}, {year}.')

	# get lib path
	lib_path = f'crypto_codebases/{lib}/{lib}_{year}/ccn_lib'
	lib_dir = os.listdir(lib_path)

	if len(lib_dir) == 0:
		print(f'Empty directory for: {lib} - {year}')

	os.system(f'lizard -l {language} {lib_path} -o ccn_raw/{lib}/lizard_output_{lib}_{year}.csv')

def delete_existing_results_file():
	if os.path.exists('ccn_overall.csv'):
		os.remove('ccn_overall.csv')

def write_ccn_to_file(lib, year, ccn_val):
	with open('ccn_overall.csv', 'a') as results_file:
		csv_out = csv.writer(results_file, delimiter=',')
		round_ccn = round(ccn_val, 2)
		csv_out.writerow([lib,year,round_ccn])
	results_file.close()

def get_regular_ccn(lib_name):
	class_to_ccn = {}
	with open(f'{lib_name}/{lib_name}_2022/ccn_lib/{lib_name}_2022.txt', 'r') as lib_ccns:
		ccn_arr = csv.reader(lib_ccns, delimiter=',')
		for line in ccn_arr:

			try:
				file_name = line[6]
				function_nloc = int(line[0])
				function_ccn = int(line[1])

				if file_name in class_to_ccn:
					
					updated_arr = class_to_ccn[file_name] + [function_nloc, function_ccn, 1]
					class_to_ccn[file_name] = updated_arr
				else:
					function_count = 0
					class_to_ccn[file_name] = [function_nloc, function_ccn, function_count]
			except:
				print("Error parsing the line.")

	return class_to_ccn

def get_class_ccns_small(lib_name):
	class_to_ccn = {}
	with open(f'{lib_name}/{lib_name}_2022/ccn_lib/{lib_name}_2022.txt', 'r') as lib_ccns:
		ccn_arr = csv.reader(lib_ccns, delimiter=',')
		for line in ccn_arr:
			try:
				file_name = line[6]
				function_nloc = line[0]
				function_ccn = line[1]

				# Only add functions of more than one line
				if int(function_nloc) > 4:
					if file_name in class_to_ccn:
						updated_arr = class_to_ccn[file_name] + [function_nloc, function_ccn]
						class_to_ccn[file_name] = updated_arr
					else:
						class_to_ccn[file_name] = [function_nloc, function_ccn]
			except:
				print("Error parsing the line.")

	return class_to_ccn

def calculate_ccn_class_avg(class_to_ccn):
	ccn_total = 0
	class_total = 0

	for e in class_to_ccn:
		ccn_total += int(class_to_ccn[e][1])
		class_total += 1

	ccn_val = ccn_total / class_total
	print("Class total:")
	print(class_total)
	print("Class CCN value:")
	print(ccn_val)

def calculate_ccn_func_avg(lib_name):
	ccn_total = 0
	func_total = 0

	with open(f'{lib_name}/{lib_name}_2022/ccn_lib/{lib_name}_2022.txt', 'r') as lib_ccns:
		ccn_arr = csv.reader(lib_ccns, delimiter=',')
		for line in ccn_arr:
			try:
				#file_name = line[6]
				# function_nloc = line[0]
				function_ccn = line[1]

				ccn_total += int(function_ccn)
				func_total += 1
			except:
				print("Error parsing the line.")

	ccn_val = ccn_total / func_total
	print("Function total:")
	print(func_total)
	print("Function CCN value:")
	print(ccn_val)

def calculate_ccn_large_func_avg(lib_name, year):
	ccn_total = 0
	func_count = 0

	with open(f'ccn_raw/{lib_name}/lizard_output_{lib_name}_{year}.csv', 'r') as lib_ccns:
		ccn_arr = csv.reader(lib_ccns, delimiter=',')
		for line in ccn_arr:
			try:
				function_nloc = line[0]
				function_ccn = line[1]

				# Only add functions of more than one line to avoid getters/setters
				if int(function_nloc) > 4:
					ccn_total += int(function_ccn)
					func_count += 1
			except:
				print("Error parsing lizard output.")

	ccn_val = ccn_total / func_count

	return ccn_val

def run_ccn_analysis(lib, years, lang):
	# Make sub-directories
	make_dir(f'ccn_raw/{lib}')

	for year in years:
		run_lizard(lib, year, lang)

		ccn_val = calculate_ccn_large_func_avg(lib, year)
		write_ccn_to_file(lib, year, ccn_val)

def calculate_overall_ccn():
	for lib, years in libraries_python.items():
		run_ccn_analysis(lib, years, 'python')

	for lib, years in libraries_rust.items():
		run_ccn_analysis(lib, years, 'rust')

	for lib, years in libraries_java.items():
		run_ccn_analysis(lib, years, 'java')

	for lib, years in libraries_c.items():
		run_ccn_analysis(lib, years, 'cpp')

	for lib, years in libraries_go.items():
		run_ccn_analysis(lib, years, 'go')


delete_existing_results_file()

calculate_overall_ccn()


