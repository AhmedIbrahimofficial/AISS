from dotenv import load_dotenv
import os, sys
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
sys.path.insert(0, os.path.dirname(__file__))
from modules.geo_lookup import GEOIP_DB_PATH, is_available
print("GEOIP_DB_PATH:", GEOIP_DB_PATH)
print("File exists:", os.path.exists(GEOIP_DB_PATH))
print("GeoIP available:", is_available())
