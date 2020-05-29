import math
import secrets

def lcm(val1, val2):
    return abs(val1 * val2) // math.gcd(val1, val2)

