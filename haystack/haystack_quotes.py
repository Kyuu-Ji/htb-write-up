import requests, json
from googletrans import Translator

r = requests.get('http://10.10.10.115:9200/quotes/_search?size=253')
quotes = json.loads(r.text)

translator = Translator()

for quote in quotes['hits']['hits']:
    q = quote['_source']['quote']
    qt = (translator.translate(q)).text
    print(qt)
    print()
