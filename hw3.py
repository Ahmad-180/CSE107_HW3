from hashlib import sha3_256
from Crypto.Cipher.ChaCha20_Poly1305 import new as AE
import math

def warmup(g, p, ga, b):
	"""
	Warm-up problem (1 point): Finish the Diffie-Hellman handshake!

	Alice has sent you g^a mod p. You've chosen your secret value b at random.
	What do you send to Alice? And what is your shared secret with Alice?

	Fill in this function to return a pair (value to send to Alice, shared secret)
	"""

	## Python notes:
	# In Python, if you write x^y, this is NOT exponentiation, it's bitwise XOR.
	# Instead for exponentiation you would write x**y or pow(x,y)
	# To compute x^y mod z, you can write x**y % z
	# Better yet, use three-argument pow: pow(x,y,z)
	# pow(x,y,z) is much faster than (x**y % z) when y is very large,
	# because it reduces mod z as it goes, rather than computing x**y first.
	## 

	# TODO: your code here
	gb= pow(g,b,p)
	shared = pow(ga,b,p)

	return gb, shared

def bsgs(g, gx, p):
	"""
	Problem 2 (5 points): Finding discrete logs mod p in O(sqrt(p)) time

	This function takes in:
	g, gx, and p
	and should return x such that gx == g**x mod p, and do so in O(sqrt(p)) time.
	
	The brute-force approach of trying all possible x takes O(p) time: too slow.
	Instead, you should implement the baby-steps-giant-steps algorithm discussed in class,
	which takes time O(sqrt(p)). See the lecture slides for more details.
	(If you prefer, you can instead implement Pollard's rho algorithm, which also takes
	time O(sqrt(p)).)
	"""

	## Python notes
	# 1) For modular exponentiation, instead of x**y % z, use pow(x,y,z), which is much faster.
	# 2) You can create and use a hashtable like this:
	#     d = dict()
	#     d["key"] = "value"
	#     d[7] = 123 # lookup keys can also be numbers or tuples (but not lists)...
	#     d[100] = ["a", "b", "c"] # ...while values can be of any type.
	#     if 7 in d: # checks if a key is present
	#     	print("d[7] is:", d[7]) # it's 123
	#     for k in d: # iterates through keys
	#     	print("key", k, "maps to value", d[k])
	#     del d["key"] # to delete an entry 
	##

	# TODO: your code here
	m= math.isqrt(p-1) +1
	baby = {pow(g, j,p): j for j in range(m)}
	g_inv_m = pow(g, p-1 -m,p)
	gamma = gx
	for i in range(m):
		if gamma in baby:
			return i* m + baby[gamma]
		gamma = (gamma * g_inv_m) % p
	return None


def break_DH_handshake(g, p, ga, gb, ctxt):
	"""
	Problem 3 (4 points): Breaking Diffie-Hellman by breaking discrete log

	You're the attacker Eve, eavesdropping on Alice and Bob's communication.
	You are given as input a transcript of a DH handshake, consisting of:
	g, p: public DH parameters
	ga: Alice's keyshare, which is g**a mod p
	gb: Bob's keyshare, which is g**b mod p
	ctxt: a ciphertext encrypted using a key derived from g**{ab} mod p

	Your task is to return the plaintext (i.e., find the key and decrypt ctxt)
	taking no more than O(sqrt(p)) time.

	You should first recover g**{ab} with the help of your bsgs function,
	then call the helper function D(gab, ctxt) to decrypt the ciphertext.
	We've already implemented D below.
	"""

	# TODO: your code here
	...
	return b"TODO return the plaintext"


## You don't need to (and should not) modify anything below. It's used for testing your code locally.

def E(gab, msg):
	"""
	Utility function that derives a symmetric key from g^{ab} and encrypts msg using an authenticated encryption scheme
	"""
	ctxt, tag = AE(key=sha3_256(gab.to_bytes(32, byteorder="big")).digest(), nonce=b"\x00"*8).encrypt_and_digest(msg)
	return tag + ctxt
	
def D(gab, ctxt):
	"""
	Utility function that derives a symmetric key from g^{ab} and tries to decrypt ctxt using an authenticated encryption scheme 
	"""
	if type(ctxt) != bytes or len(ctxt) < 16:
		raise TypeError("ctxt must be a bytes object of length at least 16")
	if type(gab) != int:
		raise TypeError("gab must be an int")
	try:
		return AE(key=sha3_256(gab.to_bytes(32, byteorder="big")).digest(), nonce=b"\x00"*8).decrypt_and_verify(ctxt[16:], ctxt[:16])
	except ValueError:
		print("Decryption failed")
		return None

def test_bsgs():
	print("Checking bsgs...")
	print(" - checking correctness for a small prime...")
	p = 6599
	g = 13 
	x = randint(1, p-2)
	gx = pow(g, x, p)
	x2 = bsgs(g, gx, p)
	if pow(g, x2, p) != gx:
		print("Your bsgs implementation returned an incorrect answer:")
		print(f"bsgs({g}, {gx}, {p}) returned {x2}; correct answer was {x}")
		return	
	else:
		print("   ...correct for small prime.")
	print(" - checking with a big prime...")
	print("   (This should finish in well under 30 seconds; if not, your solution is too slow.)")
	p = 1305774721523
	g = 2
	x = randint(1, (p-2))
	gx = pow(g, x, p)
	x2 = bsgs(g, gx, p)
	if pow(g, x2, p) != gx:
		print("Your bsgs implementation returned an incorrect answer:")
		print(f"bsgs({g}, {gx}, {p}) returned {x2}; correct answer was {x}")
		return	
	else:
		print("   ...correct for large prime.")
	print("As long as the above test didn't take too long, your bsgs implementation looks good!")

if __name__ == "__main__":
	from random import randint

	## Test the warmup 
	print("Checking the warmup...")
	if (
		warmup(2, 887, 634, 38) != (606, 858) or
		warmup(3, 14199193645238008139, 6943175078456336185, 2600256006124115575) != (3225824577418223264, 14119976883408084160)
	):
		print(" Your solution to the warmup is incorrect.")
	else:
		print(" Your solution to the warmup looks correct!")
	print()

	## Test bsgs
	test_bsgs()
	print()

	## Test break_DH_handshake
	print("Checking break_DH_handshake()...")
	print("(This should finish in well under 30 seconds; if not, your solution is too slow and may not get credit.)")
	g = 3
	p = 1305774721523
	# 3 generates the group of order (p-1)//2
	ga = 631988101020
	gb = 76041528452
	ctxt = b'=\xeao!t\x05-\xc6\xda\x9fa\x84\x9feW\x8c\x119\xe4\x1e-p\xa8\x82\xa5a\x0b\x8c\x86x\xc3\xa2Q\xb4\xf5\x0fU\x11"r\xe3\x89\x12'

	result = break_DH_handshake(g,p,ga,gb,ctxt)
	if result:
		print("Decrypted ciphertext:")
		print(result)
		print("The autograder will check your code against a different DH transcript,")
		print("but if the above ciphertext isn't gibberish, and if your code ran in less than about 30 seconds, it should work on the autograder!")
	else:
		print("Failed to correctly decrypt the ciphertext")