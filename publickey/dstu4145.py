# DSTU 4145 - 2002
# Copyright (C) 2015  NeverWalkAloner

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see  <http://www.gnu.org/licenses/>.
import random
from publickey.ec import ECPoint


class DSTU4145:
    # Initialization of DSTU object
    # p, a, b, p_x, p_y, n - int, EC characteristics
    def __init__(self, p, a, b, p_x, p_y, n):
        self.p_point = ECPoint(p_x, p_y, a, b, p, True)
        self.a = a
        self.b = b
        self.p = p
        self.n = n

    # Generate key pair
    # d - int, private key can be specified as argument
    def gen_keys(self, d=0):
        if d == 0:
            d = random.randint(1, self.n - 1)
        dstu_d = self.n - d
        q_point = dstu_d * self.p_point
        return d, q_point

    # Sign message with private key end ephemeral key e
    # message, private_key, e - int
    def sign(self, message, private_key, e=0):
        if e == 0:
            e = random.randint(1, self.n - 1)
        r_point = e * self.p_point
        r = r_point.mult_field(r_point.x, message, self.p)
        s = (e + private_key * r) % self.n
        return r, s

    # Verify signature with public key
    # message, public_key - int
    # sign - tuple
    def verify(self, message, sign, public_key):
        p_result = sign[1] * self.p_point + sign[0] * public_key
        r = p_result.mult_field(message, p_result.x, self.p)
        if r == sign[0]:
            return True
        return False
