#!/bin/bash
echo ""
echo "  PhishGuard – Starting..."
echo ""

# Install Flask and werkzeug if needed
pip install flask werkzeug --quiet --break-system-packages 2>/dev/null || pip install flask werkzeug --quiet

# Only wipe DB if --reset flag is passed
if [[ "$1" == "--reset" ]]; then
  echo "  Resetting database..."
  rm -f training.db
fi

# Start the server
python app.py
