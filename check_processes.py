import psutil

for proc in psutil.process_iter(['name']):
    try:
        print(proc.info['name'])
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
