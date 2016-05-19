# Elliptic curve math
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
class ECPoint:
    def __init__(self, x=0, y=0, a=0, b=0, p=0, is_polynomial_basis=False):
        self.x = x
        self.y = y
        self.a = a
        self.b = b
        self.p = p
        self.pol_basis = is_polynomial_basis

    # inverse int b modulo p
    @staticmethod
    def _mod_inverse(b, p):
        x0, x1, y0, y1, n = 1, 0, 0, 1, p
        while n != 0:
            q, b, n = b // n, n, b % n
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return x0 % p

    # addition of two EC points
    def __add__(self, other):
        p_result = ECPoint()
        p_result.a = self.a
        p_result.b = self.b
        p_result.p = self.p
        p_result.pol_basis = self.pol_basis
        if self.pol_basis:
            if self.x == other.x and self.y == other.y:
                x_sqr = self.mult_field(self.x, self.x, self.p)
                p_result.x = self.sum_field(x_sqr,
                                            self.mult_field(self.b, self.inv_field(x_sqr, self.p), self.p))
                tmp1 = self.mult_field(self.y, self.inv_field(self.x, self.p), self.p)
                tmp2 = self.mult_field(self.sum_field(self.x, tmp1), p_result.x, self.p)
                p_result.y = self.sum_field(x_sqr, tmp2, p_result.x)
            else:
                if self.x == other.x:
                    return float('inf')
                l = self.mult_field(self.sum_field(self.y, other.y),
                                    self.inv_field(self.sum_field(self.x, other.x), self.p), self.p)
                p_result.x = self.sum_field(self.mult_field(l, l, self.p), l, self.x, other.x, self.a)
                l2 = self.mult_field(self.sum_field(self.y, other.y),
                                     self.inv_field(self.sum_field(self.x, other.x), self.p), self.p)
                p_result.y = self.sum_field(self.mult_field(l2, self.sum_field(self.x, p_result.x), self.p),
                                            p_result.x, self.y)
        else:
            dx = (other.x - self.x) % self.p
            dy = (other.y - self.y) % self.p
            if self.x == other.x and self.y == other.y:
                l = ((3 * self.x ** 2 + self.a) * ECPoint._mod_inverse(2 * self.y, self.p)) % self.p
            else:
                if self.x == other.x:
                    return float('inf')
                dx_inverse = ECPoint._mod_inverse(dx, self.p)
                l = (dy * dx_inverse) % self.p
            p_result.x = (l * l - self.x - other.x) % self.p
            p_result.y = (l * (self.x - p_result.x) - self.y) % self.p
        return p_result

    # multiplication EC point and integer
    def __rmul__(self, other):
        p_result = ECPoint(self.x, self.y, self.a, self.b, self.p, self.pol_basis)
        temp = ECPoint(self.x, self.y, self.a, self.b, self.p, self.pol_basis)
        x = other - 1
        while x != 0:
            if x % 2 != 0:
                p_result += temp
                x -= 1
            x //= 2
            temp = temp + temp
        return p_result

    # Multiplication in polynomial basis
    def mult_field(self, x, y, n):
        mask = 1 << (n.bit_length() - 2)
        p = 0
        while x:
            if x & 1:
                p ^= y
            if y & mask:
                y = (y << 1) ^ n
            else:
                y <<= 1
            x >>= 1
        return p

    # Addition in polynomial basis
    def sum_field(self, *x):
        res = 0
        for el in x:
            res ^= el
        return res

    # Inverse polynomial a modulo polynomial f
    def inv_field(self, a, f):
        u, v = a, f
        g1, g2, = 1, 0
        while u != 1:
            j = u.bit_length() - v.bit_length()
            if j < 0:
                u, v = v, u
                g1, g2 = g2, g1
                j = - j
            u = self.sum_field(u, (v << j))
            g1 = self.sum_field(g1, (g2 << j))
        return g1
