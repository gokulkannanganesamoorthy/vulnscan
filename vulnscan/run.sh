#!/bin/bash
# Get the directory where this script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Activate virtual environment if it exists
if [ -d "$DIR/venv" ]; then
    source "$DIR/venv/bin/activate"
else
    echo "Error: Virtual environment not found at $DIR/venv"
    exit 1
fi

# Run the python script
exec python3 "$DIR/pdf_vulnscan_updated.py" "$@"
