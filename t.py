        
import requests 

ipcheck="152.58.213.171"

try:
    response = requests.get('https://api.findip.net/' + ipcheck + '/?token=9760606036624d2d99873fd9bd59aea9', timeout=5)
    response.raise_for_status()  # Raises an HTTPError for bad responses
    ipdetails = response.json()
except (requests.RequestException, ValueError) as e:
    # Log the error (you should implement proper logging)
    print(f"Error fetching IP details: {str(e)}")
    ipdetails = {}  # Use an empty dict if the request fails


SessionData = {
    "City": ipdetails.get('city', {}).get('names', {}).get('en'),
    "Country": ipdetails.get('country', {}).get('names', {}).get('en'),
    "Latitude": ipdetails.get('location', {}).get('latitude'),
    "Longitude": ipdetails.get('location', {}).get('longitude'),
    "TimeZone": ipdetails.get('location', {}).get('time_zone'),
    "ISP": ipdetails.get('traits', {}).get('isp'),
}
    
print(SessionData)