p = r"D:\AXRE\ghax4\main.m"
s = open(p, encoding="utf-8").read()
s = s.replace("(__bridge CFDataRef)[MSG dataUsingEncoding:NSUTF8StringEncoding],\n                        (CFErrorRef *)&er));",
              "(__bridge CFDataRef)pdata,\n                        (CFErrorRef *)&er));")
open(p, "w", encoding="utf-8").write(s)
print("MSG ->", "pdata" in s)
print("remaining MSG refs:", s.count("[MSG "))
