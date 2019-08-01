
import subprocess


def switch_named_file(target,source):
	
	home = "./"

	try:
		subprocess.check_call(['ln', '-f', '-s', target, source], cwd = home)
	except subprocess.CalledProcessError:
		return False
	
	return True

target = "standard_source.zone"
#target = "exigency_source.zone"
source = "switch_root.zone"
print(switch_named_file(target,source))
