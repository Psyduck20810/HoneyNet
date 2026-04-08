import os


def load_env():
    """
    Load variables from the .env file in the project root into os.environ.
    Uses setdefault so existing env vars (e.g. from Docker) are never overridden.
    """
    env_path = os.path.join(os.path.dirname(__file__), '../.env')
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, val = line.split('=', 1)
                    os.environ.setdefault(key.strip(), val.strip())
