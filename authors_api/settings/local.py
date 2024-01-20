from .base import *
from .base import env

DEBUG = True
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env("DJANGO_SECRET_KEY", default="VWEBJKWECNDNMRNCJRNCWLL.CNE;RENVRENV",)

ALLOWED_HOSTS = ["localhost", "0.0.0.0", "127.0.0.1"]