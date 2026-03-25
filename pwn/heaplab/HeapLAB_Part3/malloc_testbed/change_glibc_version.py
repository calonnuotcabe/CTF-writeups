#!/usr/bin/python3
import os

# Grab available GLIBC versions.
available_versions = [item.name for item in os.scandir("../.glibc") if item.is_dir()]
if "malloc_testbed_glibc" in available_versions:
    available_versions.remove("malloc_testbed_glibc")
available_versions.sort()

# Print menu.
print("\n--------------------")
print("Select GLIBC version")
print("--------------------")
for c, version in enumerate(available_versions):
    print(f"{c:02}) " + version)

# Process input.
choice = int(input("> "))
if choice < len(available_versions):
    # Remove old symlink.
    try:
        os.unlink("../.glibc/malloc_testbed_glibc")
    except FileNotFoundError:
        print("No old link to remove")

    # Replace symlink.
    os.symlink(available_versions[choice], "../.glibc/malloc_testbed_glibc")
