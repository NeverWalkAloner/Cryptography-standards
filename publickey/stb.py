# STB 34.101.45-2013
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
import symmetric.belt as belt


class STB:
    # Initialization of STB object
    # p, a, b, q, g_y - int, EC characteristics
    # l - int, security bit level
    def __init__(self, p, a, b, q, g_y, l):
        self.g_point = ECPoint(0, g_y, a, b, p)
        self.q = q
        self.a = a
        self.b = b
        self.p = p
        self.l = l

    # generate key pair
    def gen_keys(self):
        d = random.randint(1, self.q - 1)
        q_point = d * self.g_point
        return d, q_point

    # sign message with private key
    # message, private_key - int
    def sign(self, message, private_key, k=0):
        if k == 0:
            k = random.randint(1, self.q-1)
        oid = 0x06092A7000020022651F51
        r_point = k * self.g_point
        hash_value = self.belt_hash(message)
        value_to_hash = int2list(oid) + int2list(reverse(r_point.x)) + int2list(hash_value)
        s0 = self.belt_hash(list2int(value_to_hash))
        s0 = int2list(s0)[:16]
        s0 = list2int(s0)
        s1 = (k - reverse(hash_value) - (reverse(s0) + 2 ** self.l) * private_key) % self.q
        return s0, reverse(s1)

    # verify signatute
    # message, sign - int
    # pub_key - tuple
    def verify(self, message, pub_key, sign):
        if sign[1] > self.q:
            return False
        public_key = ECPoint(pub_key[0], pub_key[1], self.a, self.b, self.p)
        sign_tmp = reverse(sign[0]), reverse(sign[1])
        oid = 0x06092A7000020022651F51
        hash_value = self.belt_hash(message)
        r_point = ((sign_tmp[1] + reverse(hash_value)) % self.q) * self.g_point + \
                  (sign_tmp[0] + 2 ** self.l) * public_key
        if r_point == float('inf'):
            return False
        value_to_hash = int2list(oid) + int2list(reverse(r_point.x)) + int2list(hash_value)
        t = self.belt_hash(list2int(value_to_hash))
        t = int2list(t)[:16]
        if list2int(t) != sign[0]:
            return False
        return True

    # compute belt hash of message
    # message - int
    def belt_hash(self, message):
        h = 0xB194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D
        h = int2list(h)
        bit_l = message.bit_length()
        l_message = int2list(message)
        len_dif = 8 - l_message[0].bit_length()
        bit_l += len_dif
        s = [0 for i in range(16)]
        if len(l_message) % 32 != 0:
            l_message = l_message + [0] * (32 - (len(l_message)) % 32)
        for i in range(len(l_message) // 32):
            m_list = l_message[i*32:(i+1)*32]
            m_list = m_list + h
            s = xor(s, self.sigma1(m_list))
            h = self.sigma2(m_list)
        bit_l = int2list(bit_l)
        if len(bit_l) < 16:
            bit_l = list(reversed(bit_l)) + [0] * (16 - len(bit_l))
        return list2int(self.sigma2(bit_l + s + h))

    # belt hash supporting function
    def sigma1(self, m_list):
        my_belt = belt.belt(m_list[:32])
        m = xor(m_list[32:48], m_list[48:64])
        sigma1 = xor(my_belt.encryption(m), m_list[32:48])
        sigma1 = xor(sigma1, m_list[48:64])
        return sigma1

    # belt hash supporting function
    def sigma2(self, m_list):
        s = self.sigma1(m_list)
        ones = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        teta1 = s + m_list[48:64]
        teta2 = xor(s, ones) + m_list[32:48]
        u1 = m_list[0:16]
        u2 = m_list[16:32]
        my_belt = belt.belt(teta1)
        tmp = xor(my_belt.encryption(u1), u1)
        my_belt2 = belt.belt(teta2)
        tm2 = xor(my_belt2.encryption(u2), u2)
        return tmp + tm2


# Represent number as list of bytes
def int2list(x):
    l = x.bit_length()
    if l % 8 == 0:
        l -= 8
    else:
        l -= (l % 8)
    l = list(range(l, -1, -8))
    return [x >> i & 0xff for i in l]


# Represent list of bytes as number
def list2int(x):
    l = [8 * i for i in range(len(x)-1, -1, -1)]
    return sum([x[i] << l[i] for i in range(len(x))])


# Reverse bytes of number x
def reverse(x):
    l = int2list(x)
    l.reverse()
    return list2int(l)


# XOR x and y byte array
def xor(x, y):
    return [x[i] ^ y[i] for i in range(len(x))]
