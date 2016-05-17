# GOST 34.10?2012
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


class DSGOST:
    # p - int, EC module
    # a, b - int, EC coefficients
    # q - int, order of point P
    # p_x, p_y - int, point P coordinates
    def __init__(self, p, a, b, q, p_x, p_y):
        self.p_point = ECPoint(p_x, p_y, a, b, p)
        self.q = q
        self.a = a
        self.b = b
        self.p = p

    # generate key pair
    def gen_keys(self):
        d = random.randint(1, self.q - 1)
        q_point = d * self.p_point
        return d, q_point

    # sing message
    # message - int
    # private_key - int
    def sign(self, message, private_key, k=0):
        e = message % self.q
        if e == 0:
            e = 1
        if k == 0:
            k = random.randint(1, self.q - 1)
        r = 0
        while r == 0:
            c_point = k * self.p_point
            r = c_point.x % self.q
        s = (r * private_key + k * e) % self.q
        return r, s

    # verify singed message
    # message - int
    # sign - tuple
    # public_key - ECPoint
    def verify(self, message, sign, public_key):
        e = message % self.q
        if e == 0:
            e = 1
        nu = ECPoint._mod_inverse(e, self.q)
        z1 = (sign[1] * nu) % self.q
        z2 = (-sign[0] * nu) % self.q
        c_point = z1 * self.p_point + z2 * public_key
        r = c_point.x % self.q
        if r == sign[0]:
            return True
        return False
