from hw3 import warmup

g  = 3
p  = 1_305_777_421_523
ga = 232_404_075_431          # g^a  mod p
b  = 90_962_301_226

gb, s = warmup(g, p, ga, b)
assert gb == pow(g, b, p)
assert s  == pow(ga, b, p)
print("warmup passes locally!")
