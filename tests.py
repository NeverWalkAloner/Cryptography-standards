import unittest
from publickey.ec import ECPoint
from symmetric.belt import belt
from symmetric.dstu import dstu2014
from symmetric.gost import gost2015
from publickey.dstu4145 import DSTU4145
from publickey.gost import DSGOST
from publickey.stb import reverse, STB
import binascii


class TestEcrypto(unittest.TestCase):
    def test_belt_encr(self):
        key = list(binascii.unhexlify('E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6'))
        belt1 = belt(key)
        m = list(binascii.unhexlify('B194BAC80A08F53B366D008E584A5DE4'))
        c1 = binascii.hexlify(bytearray(belt1.encryption(m)))
        self.assertEqual(c1, b'69cca1c93557c9e3d66bc3e0fa88fa6e')

    def test_belt_decr(self):
        c = list(binascii.unhexlify('E12BDC1AE28257EC703FCCF095EE8DF1'))
        key2 = list(binascii.unhexlify('92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511'))
        belt2 = belt(key2)
        d1 = binascii.hexlify(bytearray(belt2.decryption(c)))
        self.assertEqual(d1, b'0dc5300600cab840b38448e5e993f421')

    def test_dstu_enc(self):
        key = list(binascii.unhexlify('000102030405060708090a0b0c0d0e0f'))
        pt = list(binascii.unhexlify('101112131415161718191a1b1c1d1e1f'))
        dstu =dstu2014(key)
        self.assertEqual(binascii.hexlify(bytearray(dstu.encryption(pt))), b'81bf1c7d779bac20e1c9ea39b4d2ad06')

    def test_dst_dec(self):
        key2 = list(binascii.unhexlify('0f0e0d0c0b0a09080706050403020100'))
        ct = list(binascii.unhexlify('1f1e1d1c1b1a19181716151413121110'))
        dstu2 = dstu2014(key2)
        self.assertEqual(binascii.hexlify(bytearray(dstu2.decryption(ct))), b'7291ef2b470cc7846f09c2303973dad7')

    def test_gost_enc(self):
        mtest = list(binascii.unhexlify('1122334455667700ffeeddccbbaa9988'))
        ktest = list(binascii.unhexlify('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef'))
        gost =gost2015(ktest)
        c = gost.encryption(mtest)
        self.assertEqual(binascii.hexlify(bytearray(c)), b'7f679d90bebc24305a468d42b9d4edcd')

    def test_gost_dec(self):
        mtest = list(binascii.unhexlify('1122334455667700ffeeddccbbaa9988'))
        ktest = list(binascii.unhexlify('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef'))
        gost =gost2015(ktest)
        c = gost.encryption(mtest)
        d = gost.decryption(c)
        self.assertEqual(binascii.hexlify(bytearray(d)), b'1122334455667700ffeeddccbbaa9988')

    def test_dstu_sign(self):
        dstu_x = 0x72D867F93A93AC27DF9FF01AFFE74885C8C540420
        dstu_y = 0x0224A9C3947852B97C5599D5F4AB81122ADC3FD9B
        dstu_a = 0x1
        dstu_b = 0x5FF6108462A2DC8210AB403925E638A19C1455D21
        dstu_p = 0x800000000000000000000000000000000000000c9
        dstu_n = 0x400000000000000000002BEC12BE2262D39BCF14D
        dstu = DSTU4145(dstu_p, dstu_a, dstu_b, dstu_x, dstu_y, dstu_n)
        message = 0x03A2EB95B7180166DDF73532EEB76EDAEF52247FF
        dstu_d = 0x183F60FDF7951FF47D67193F8D073790C1C9B5A3E
        dstu_e = 0x1025E40BD97DB012B7A1D79DE8E12932D247F61C6
        signature = dstu.sign(message, dstu_d, dstu_e)
        expected = (0x274EA2C0CAA014A0D80A424F59ADE7A93068D08A7, 0x2100D86957331832B8E8C230F5BD6A332B3615ACA)
        self.assertEqual(signature, expected)

    def test_dstu_verify(self):
        dstu_x = 0x72D867F93A93AC27DF9FF01AFFE74885C8C540420
        dstu_y = 0x0224A9C3947852B97C5599D5F4AB81122ADC3FD9B
        dstu_a = 0x1
        dstu_b = 0x5FF6108462A2DC8210AB403925E638A19C1455D21
        dstu_p = 0x800000000000000000000000000000000000000c9
        dstu_n = 0x400000000000000000002BEC12BE2262D39BCF14D
        dstu = DSTU4145(dstu_p, dstu_a, dstu_b, dstu_x, dstu_y, dstu_n)
        message = 0x03A2EB95B7180166DDF73532EEB76EDAEF52247FF
        dstu_d = 0x183F60FDF7951FF47D67193F8D073790C1C9B5A3E
        dstu_Q = dstu.gen_keys(dstu_d)[1]
        signature = (0x274EA2C0CAA014A0D80A424F59ADE7A93068D08A7, 0x2100D86957331832B8E8C230F5BD6A332B3615ACA)
        self.assertEqual(dstu.verify(message, signature, dstu_Q), True)

    def test_gost_sign(self):
        p = 57896044618658097711785492504343953926634992332820282019728792003956564821041
        a = 7
        b = 3308876546767276905765904595650931995942111794451039583252968842033849580414
        x = 2
        y = 4018974056539037503335449422937059775635739389905545080690979365213431566280
        q = 57896044618658097711785492504343953927082934583725450622380973592137631069619
        gost = DSGOST(p, a, b, q, x, y)
        key = 55441196065363246126355624130324183196576709222340016572108097750006097525544
        message = 20798893674476452017134061561508270130637142515379653289952617252661468872421
        k = 53854137677348463731403841147996619241504003434302020712960838528893196233395
        sign = gost.sign(message, key, k)
        expected = (29700980915817952874371204983938256990422752107994319651632687982059210933395,
                    574973400270084654178925310019147038455227042649098563933718999175515839552)
        self.assertEqual(sign, expected)

    def test_gost_verify(self):
        p = 57896044618658097711785492504343953926634992332820282019728792003956564821041
        a = 7
        b = 3308876546767276905765904595650931995942111794451039583252968842033849580414
        x = 2
        y = 4018974056539037503335449422937059775635739389905545080690979365213431566280
        q = 57896044618658097711785492504343953927082934583725450622380973592137631069619
        gost = DSGOST(p, a, b, q, x, y)
        message = 20798893674476452017134061561508270130637142515379653289952617252661468872421
        sign = (29700980915817952874371204983938256990422752107994319651632687982059210933395,
                    574973400270084654178925310019147038455227042649098563933718999175515839552)
        q_x = 57520216126176808443631405023338071176630104906313632182896741342206604859403
        q_y = 17614944419213781543809391949654080031942662045363639260709847859438286763994
        public_key = ECPoint(q_x, q_y, a, b, p)
        self.assertEqual(gost.verify(message, sign, public_key), True)

    def test_stb_sign(self):
        p = 0x43FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        p = reverse(p)
        a = 0x40FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        a = reverse(a)
        b = 0xF1039CD66B7D2EB253928B976950F54CBEFBD8E4AB3AC1D2EDA8F315156CCE77
        b = reverse(b)
        q = 0x07663D2699BF5A7EFC4DFB0DD68E5CD9FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        q = reverse(q)
        y = 0x936A510418CF291E52F608C4663991785D83D651A3C9E45C9FD616FB3CFCF76B
        y = reverse(y)
        d = 0x1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269
        d = reverse(d)
        stb = STB(p, a, b, q, y, 128)
        message = 0xB194BAC80A08F53B366D008E58
        k = 0x4C0E74B2CD5811AD21F23DE7E0FA742C3ED6EC483C461CE15C33A77AA308B7D2
        k = reverse(k)
        signature = stb.sign(message, d, k)
        expected = (0xE36B7F0377AE4C524027C387FADF1B20,
                    0xCE72F1530B71F2B5FD3A8C584FE2E1AED20082E30C8AF65011F4FB54649DFD3D)
        self.assertEqual(signature, expected)

    def test_stb_verify(self):
        p = 0x43FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        p = reverse(p)
        a = 0x40FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        a = reverse(a)
        b = 0xF1039CD66B7D2EB253928B976950F54CBEFBD8E4AB3AC1D2EDA8F315156CCE77
        b = reverse(b)
        q = 0x07663D2699BF5A7EFC4DFB0DD68E5CD9FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        q = reverse(q)
        y = 0x936A510418CF291E52F608C4663991785D83D651A3C9E45C9FD616FB3CFCF76B
        y = reverse(y)
        message = 0xB194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B
        q_x = 0xBD1A5650179D79E03FCEE49D4C2BD5DDF54CE46D0CF11E4FF87BF7A890857FD0
        q_x = reverse(q_x)
        q_y = 0x7AC6A60361E8C8173491686D461B2826190C2EDA5909054A9AB84D2AB9D99A90
        q_y = reverse(q_y)
        s = (0x47A63C8B9C936E94B5FAB3D9CBD78366, 0x290F3210E163EEC8DB4E921E8479D4138F112CC23E6DCE65EC5FF21DF4231C28)
        pub_key = (q_x, q_y)
        stb = STB(p, a, b, q, y, 128)
        self.assertEqual(stb.verify(message, pub_key, s), True)

if __name__ == '__main__':
    unittest.main()
