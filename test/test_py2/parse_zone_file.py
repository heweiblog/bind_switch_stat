
from iscpy.iscpy_dns.named_importer_lib import *

def get_root_file_size():
	#root_source_file = '/var/named/named.ca'
	#root_source_file = 'local-rootzone'
	root_source_file = 'standard_root.zone'
	try:
		with open(root_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			print(named_data)
			server = named_data['orphan_zones']['.']['options']['masters']
			print(server)
			#server = named_data['orphan_zones']['.']['options']['server-address']
			#root_copy_list = []
			#for k in server:
				#root_copy_list.append(k)
			#print(root_copy_list)
	except Exception as e:
		print(e)

get_root_file_size()

