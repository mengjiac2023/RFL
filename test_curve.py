# example taken from the document below (section 4.3.2):
# https://koclab.cs.ucsb.edu/teaching/cren/docs/w02/nist-routines.pdf
import time
from fastecdsa.curve import P256
from fastecdsa.point import Point

xs = 0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9
ys = 0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256
S = Point(xs, ys, curve=P256)

xt = 0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b
yt = 0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316
T = Point(xt, yt, curve=P256)
t= time.time()
for _ in range(100):
    # Point Addition
    R = S + T
print("addition time: {}".format((time.time()-t)/100))
# Point Subtraction: (xs, ys) - (xt, yt) = (xs, ys) + (xt, -yt)
R = S - T

# Point Doubling
R = S + S  # produces the same value as the operation below
R = 2 * S  # S * 2 works fine too i.e. order doesn't matter

d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
t = time.time()
for _ in range(100):
    # Scalar Multiplication
    R = d * S  # S * d works fine too i.e. order doesn't matter
print("multiplication time: {:.6f} second".format((time.time()-t)/100))
e = 0xd37f628ece72a462f0145cbefe3f0b355ee8332d37acdd83a358016aea029db7

# Joint Scalar Multiplication
R = d * S + e * T
