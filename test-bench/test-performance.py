import time
import psutil  # For monitoring system performance

# Function to measure system performance
def measure_performance(duration=10):
    cpu_usage = []
    mem_usage = []
    start_time = time.time()
    while time.time() - start_time < duration:
        cpu_usage.append(psutil.cpu_percent(interval=1))
        mem_usage.append(psutil.virtual_memory().percent)
    return cpu_usage, mem_usage

# Run performance measurement
cpu_usage, mem_usage = measure_performance()

# Output results
print("CPU Usage (%):", cpu_usage)
print("Memory Usage (%):", mem_usage)

