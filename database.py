import pymongo
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv('MONGO_URI')
mongo = pymongo.MongoClient(MONGO_URI)
