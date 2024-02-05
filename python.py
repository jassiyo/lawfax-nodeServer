import requests
import base64

url = "http://34.105.29.122:8000/law_sections/"
files = {"pdf_file": open("SS_NIAPOLICYSCHEDULECIRTIFICATESS_44081908.pdf", "rb")}


#params["random_string"] = random_string

params = {
    "state": "Punjab",
    "case_no": "101",
    "description": "not able to claim my insurance",
    "history": "none",
    "District": "Baithinda",
    "town": "Bathindiiiii",
    "case_type": "Insurance",
    "full_name": "ENGINEER CONSTRUCTIONS PVT LTD",
    "address": "LANE 6, CANAL ROAD GHUMANIWALA, Bathinda - 249204 Tel. 9756877006"
}

response = requests.post(url,files=files, params=params)
print(response.json())