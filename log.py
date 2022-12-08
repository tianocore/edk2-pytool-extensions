import platform

host_info = platform.uname()
print(host_info.system)
print(host_info.machine)