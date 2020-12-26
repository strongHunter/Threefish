public class SupportingTools {
    protected static final class TwoArgs {
        final long a;
        final long b;

        TwoArgs(long a, long b) {
            this.a = a;
            this.b = b;
        }
    }

    protected static long reverse(long l) {
        long result = 0;

        for (int i = 0; i < 8; i++) {
            result <<= 8;
            result |= l & 0xFF;
            l >>>= 8;
        }

        return result;
    }

    protected static long[] bytesToLongs(byte[] b, int length) {
        long[] result = new long[length];

        for (int i = 0; i < length; i++)
            for (int j = 0; j < 8; j++)
                if (i * 8 + j < b.length) {
                    result[i] <<= 8;
                    result[i] |= (b[i * 8 + j] & 0xFF);
                }
        return result;
    }

    protected static long bytesToLong(byte[] b) {
        long result = 0;

        for (int j = 0; j < 8; j++)
            if (j < b.length) {
                result <<= 8;
                result |= (b[j] & 0xFF);
            }
        return result;
    }

    protected static byte[] longsToBytes(long[] l) {
        byte[] result = new byte[l.length * 8];

        for (int i = 0; i < l.length; i++)
            for (int j = 7; j >= 0; j--) {
                result[i * 8 + j] |= (l[i] & 0xFF);
                l[i] >>>= 8;
            }

        return result;
    }

    protected static byte[] longToBytes(long l) {
        byte[] result = new byte[8];

        for (int j = 7; j >= 0; j--) {
            result[j] |= (l & 0xFF);
            l >>>= 8;
        }

        return result;
    }

    static boolean checkControlSums() {
        boolean result = true;

        // Контрольные значения взяты из официального источника
        // https://www.schneier.com/academic/skein/threefish/ ->
        // https://www.schneier.com/wp-content/uploads/2015/01/skein.zip ->
        // NIST\CD\KAT_MCT\skein_golden_kat_internals.txt
        long[] checkSum256_1 = {0x94EEEA8B1F2ADA84L, 0xADF103313EAE6670L, 0x952419A1F4B16D53L, 0xD83F13E63C9F6B11L};
        long[] checkSum256_2 = {0x277610F5036C2E1FL, 0x25FB2ADD1267773EL, 0x9E1D67B3E4B06872L, 0x3F76BC7651B39682L};

        long[] checkSum512_1 = {0xBC2560EFC6BBA2B1L, 0xE3361F162238EB40L, 0xFB8631EE0ABBD175L, 0x7B9479D4C5479ED1L,
                0xCFF0356E58F8C27BL, 0xB1B7B08430F0E7F7L, 0xE9A380A56139ABF1L, 0xBE7B6D4AA11EB47EL};
        long[] checkSum512_2 = {0xD4A32EDD6ABEFA1CL, 0x6AD5C4252C3FF743L, 0x35AC875BE2DED68CL, 0x99A6C774EA5CD06CL,
                0xDCEC9C4251D7F4F8L, 0xF5761BCB3EF592AFL, 0xFCABCB6A3212DF60L, 0xFD6EDE9FF9A2E14EL};

        long[] checkSum1024_1 = {0x04B3053D0A3D5CF0L, 0x0136E0D1C7DD85F7L, 0x067B212F6EA78A5CL, 0x0DA9C10B4C54E1C6L,
                0x0F4EC27394CBACF0L, 0x32437F0568EA4FD5L, 0xCFF56D1D7654B49CL, 0xA2D5FB14369B2E7BL,
                0x540306B460472E0BL, 0x71C18254BCEA820DL, 0xC36B4068BEAF32C8L, 0xFA4329597A360095L,
                0xC4A36C28434A5B9AL, 0xD54331444B1046CFL, 0xDF11834830B2A460L, 0x1E39E8DFE1F7EE4FL};
        long[] checkSum1024_2 = {0x483AC62C27B09B59L, 0x4CB85AA9E48221AAL, 0x80BC1644069F7D0BL, 0xFCB26748FF92B235L,
                0xE83D70243B5D294BL, 0x316A3CA3587A0E02L, 0x5461FD7C8EF6C1B9L, 0x7DD5C1A4C98CA574L,
                0xFDA694875AA31A35L, 0x03D1319C26C2624CL, 0xA2066D0DF2BF7827L, 0x6831CCDAA5C8A370L,
                0x2B8FCD9189698DACL, 0xE47818BBFD604399L, 0xDF47E519CBCEA541L, 0x5EFD5FF4A5D4C259L};


        long[] testNullTweak = {0, 0};
        long[] testTweak = {0x0706050403020100L, 0x0F0E0D0C0B0A0908L};
        for (long element : testTweak) element = SupportingTools.reverse(element);


        System.out.println("256");

        long[] test256Key_1 = {0, 0, 0, 0};
        ThreeFish test256Cipher_1 = new ThreeFish(test256Key_1, testNullTweak, 256);
        byte[] test256Buf_1 = new byte[256 / 8];
        test256Buf_1 = test256Cipher_1.encrypt(test256Buf_1);
        long[] res256_1 = SupportingTools.bytesToLongs(test256Buf_1, test256Buf_1.length / 8);
        for (int i = 0; i < res256_1.length; i++)
            if (res256_1[i] != checkSum256_1[i]) {
                result = false;
                break;
            }
        if (result)
            System.out.println("ok");
        else
            System.out.println("bad");


        long[] test256Key_2 = {0x1716151413121110L, 0x1F1E1D1C1B1A1918L, 0x2726252423222120L, 0x2F2E2D2C2B2A2928L};
        for (long element : test256Key_2) element = SupportingTools.reverse(element);
        ThreeFish test256Cipher_2 = new ThreeFish(test256Key_2, testTweak, 256);
        long[] tmp256 = {0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L};
        for (long element : tmp256) element = SupportingTools.reverse(element);
        long[] plaintText256 = new long[tmp256.length];
        System.arraycopy(tmp256, 0, plaintText256, 0, tmp256.length);
        byte[] test256Buf_2 = SupportingTools.longsToBytes(tmp256);
        test256Buf_2 = test256Cipher_2.encrypt(test256Buf_2);
        long[] res256_2 = SupportingTools.bytesToLongs(test256Buf_2, test256Buf_2.length / 8);
        for (int i = 0; i < res256_2.length; i++)
            if ((res256_2[i] ^ plaintText256[i]) != checkSum256_2[i]) {
                result = false;
                break;
            }
        if (result)
            System.out.println("ok");
        else
            System.out.println("bad");



        System.out.println("512");

        long[] test512Key_1 = {0, 0, 0, 0, 0, 0, 0, 0};
        ThreeFish test512Cipher_1 = new ThreeFish(test512Key_1, testNullTweak, 512);
        byte[] test512Buf_1 = new byte[512 / 8];
        test512Buf_1 = test512Cipher_1.encrypt(test512Buf_1);
        long[] res512_1 = SupportingTools.bytesToLongs(test512Buf_1, test512Buf_1.length / 8);
        for (int i = 0; i < res512_1.length; i++)
            if (res512_1[i] != checkSum512_1[i]) {
                result = false;
                break;
            }
        if (result)
            System.out.println("ok");
        else
            System.out.println("bad");


        long[] test512Key_2 = {0x1716151413121110L, 0x1F1E1D1C1B1A1918L, 0x2726252423222120L, 0x2F2E2D2C2B2A2928L,
                0x3736353433323130L, 0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L};
        for (long element : test512Key_2) element = SupportingTools.reverse(element);
        ThreeFish test512Cipher_2 = new ThreeFish(test512Key_2, testTweak, 512);
        long[] tmp512 = {0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L,
                0xD8D9DADBDCDDDEDFL, 0xD0D1D2D3D4D5D6D7L, 0xC8C9CACBCCCDCECFL, 0xC0C1C2C3C4C5C6C7L};
        for (long element : tmp512) element = SupportingTools.reverse(element);
        long[] plaintText512 = new long[tmp512.length];
        System.arraycopy(tmp512, 0, plaintText512, 0, tmp512.length);
        byte[] test512Buf_2 = SupportingTools.longsToBytes(tmp512);
        test512Buf_2 = test512Cipher_2.encrypt(test512Buf_2);
        long[] res512_2 = SupportingTools.bytesToLongs(test512Buf_2, test512Buf_2.length / 8);
        for (int i = 0; i < res512_2.length; i++)
            if ((res512_2[i] ^ plaintText512[i]) != checkSum512_2[i]) {
                result = false;
                break;
            }
        if (result)
            System.out.println("ok");
        else
            System.out.println("bad");



        System.out.println("1024");

        long[] test1024Key_1 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        ThreeFish test1024Cipher_1 = new ThreeFish(test1024Key_1, testNullTweak, 1024);
        byte[] test1024Buf_1 = new byte[1024 / 8];
        test1024Buf_1 = test1024Cipher_1.encrypt(test1024Buf_1);
        long[] res1024_1 = SupportingTools.bytesToLongs(test1024Buf_1, test1024Buf_1.length / 8);
        for (int i = 0; i < res1024_1.length; i++)
            if (res1024_1[i] != checkSum1024_1[i]) {
                result = false;
                break;
            }
        if (result)
            System.out.println("ok");
        else
            System.out.println("bad");


        long[] test1024Key_2 = {0x1716151413121110L, 0x1F1E1D1C1B1A1918L, 0x2726252423222120L, 0x2F2E2D2C2B2A2928L,
                0x3736353433323130L, 0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L,
                0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L, 0x6F6E6D6C6B6A6968L,
                0x7776757473727170L, 0x7F7E7D7C7B7A7978L, 0x8786858483828180L, 0x8F8E8D8C8B8A8988L};
        for (long element : test1024Key_2) element = SupportingTools.reverse(element);
        ThreeFish test1024Cipher_2 = new ThreeFish(test1024Key_2, testTweak, 1024);
        long[] tmp1024 = {0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L,
                0xD8D9DADBDCDDDEDFL, 0xD0D1D2D3D4D5D6D7L, 0xC8C9CACBCCCDCECFL, 0xC0C1C2C3C4C5C6C7L,
                0xB8B9BABBBCBDBEBFL, 0xB0B1B2B3B4B5B6B7L, 0xA8A9AAABACADAEAFL, 0xA0A1A2A3A4A5A6A7L,
                0x98999A9B9C9D9E9FL, 0x9091929394959697L, 0x88898A8B8C8D8E8FL, 0x8081828384858687L};
        for (long element : tmp1024) element = SupportingTools.reverse(element);
        long[] plaintText1024 = new long[tmp1024.length];
        System.arraycopy(tmp1024, 0, plaintText1024, 0, tmp1024.length);
        byte[] test1024Buf_2 = SupportingTools.longsToBytes(tmp1024);
        test1024Buf_2 = test1024Cipher_2.encrypt(test1024Buf_2);
        long[] res1024_2 = SupportingTools.bytesToLongs(test1024Buf_2, test1024Buf_2.length / 8);
        for (int i = 0; i < res1024_2.length; i++)
            if ((res1024_2[i] ^ plaintText1024[i]) != checkSum1024_2[i]) {
                result = false;
                break;
            }
        if (result)
            System.out.println("ok");
        else
            System.out.println("bad");


        return result;
    }
}
