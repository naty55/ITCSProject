import logging 
import os 

client_id = os.environ["client_id"].strip()
logger = logging.getLogger("E2EE client")
logging.basicConfig(filename=f'client-{client_id}.log', encoding='utf-8', level=logging.DEBUG)



