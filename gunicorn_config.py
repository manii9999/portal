# gunicorn_config.py
bind = "0.0.0.0:5000"  # Replace with the host and port you want to use
workers = 4  # Number of worker processes
timeout = 60  # Set a suitable timeout

