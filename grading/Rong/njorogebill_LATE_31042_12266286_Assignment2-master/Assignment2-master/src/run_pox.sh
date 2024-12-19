#!/bin/bash

# Define the path to pox.py relative to the script location
POX_PATH="../pox/pox.py"

# Check if pox.py exists in the specified directory
if [ ! -f "$POX_PATH" ]; then
    echo "Error: pox.py not found at $POX_PATH"
    exit 1
fi

# Run pox.py with the specified modules
python "$POX_PATH" cs414.ofhandler cs414.srhandler