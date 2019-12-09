import geoip2.database
ip = '198.252.206.16'
reader = geoip2.database.Reader('GeoLite2-City.mmdb')
response = reader.city(ip)
print(ip + " : " + str(response.location.longitude) + ", " + str(response.location.latitude) + " " + str(response.country.name) )

