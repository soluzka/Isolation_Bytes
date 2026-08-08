import yara
r = yara.compile(source='rule Test { condition: extension == ".aspx" }', externals={'extension': ''})
m1 = r.match(data=b'test', externals={'extension': '.aspx'})
m2 = r.match(data=b'test', externals={'extension': '.txt'})
print('matches with .aspx:', m1)
print('matches with .txt:', m2)
