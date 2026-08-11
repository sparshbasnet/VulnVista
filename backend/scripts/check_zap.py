import urllib.request
req = urllib.request.Request('http://zap:8080/JSON/core/view/version/', headers={'X-ZAP-API-Key':'vulnvista-dev-key'})
print(urllib.request.urlopen(req).read())
