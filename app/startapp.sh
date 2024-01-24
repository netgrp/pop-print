#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source $SCRIPT_DIR/../printenv/bin/activate
python -m flask --app $SCRIPT_DIR/printrest run --host=0.0.0.0 --port 8000 --debug

