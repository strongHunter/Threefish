public class ThreeFish{
    protected static final class CipherError extends RuntimeException {
        String message;

        CipherError() {
            message = "Unknown error of class ThreeFish";
        }

        CipherError(String str) {
            message = str;
        }

        public String toString() {
            return message;
        }
    }


    private long rotateLeft(long value, int n) {
        return (value << n) | (value >>> 64 - n);
    }

    private long rotateRight(long value, int n) {
        return (value << 64 - n) | (value >>> n);
    }

    private SupportingTools.TwoArgs mix(long x0 , long x1, int d, int j) {
        long y0 = x0 + x1;
        long y1 = rotateLeft(x1, rotationConst[j][d]) ^ y0;

        return new SupportingTools.TwoArgs(y0, y1);
    }

    private SupportingTools.TwoArgs demix(long y0, long y1, int d, int j) {
        long x1 = rotateRight(y1 ^ y0, rotationConst[j][d]);
        long x0 = y0 - x1;

        return new SupportingTools.TwoArgs(x0, x1);
    }


    private final int nw;
    private final int nr;

    private final int[][] rotationConst;
    private final int[] permutation;
    private final int[] reversePermutation;

    private final long[] key;
    private final long[] tweak = new long[3];

    private final long[][] subkey;


    public <T, E> ThreeFish(E key, T tweak, int blockSize) throws CipherError {
        if (blockSize == 256) {
            nr = 72;
            nw = 4;

            permutation = new int[]{0, 3, 2, 1};
            reversePermutation = permutation;
            rotationConst = new int[][]{
                    {14, 52, 23, 5, 25, 46, 58, 32},
                    {16, 57, 40, 37, 33, 12, 22, 32}
            };
        } else if (blockSize == 512) {
            nr = 72;
            nw = 8;

            permutation = new int[]         {2, 1, 4, 7, 6, 5, 0, 3};
            reversePermutation = new int[]  {6, 1, 0, 7, 2, 5, 4, 3};
            rotationConst = new int[][]{
                    {46, 33, 17, 44, 39, 13, 25, 8},
                    {36, 27, 49, 9, 30, 50, 29, 35},
                    {19, 14, 36, 54, 34, 10, 39, 56},
                    {37, 42, 39, 56, 24, 17, 43, 22}
            };
        } else if (blockSize == 1024) {
            nr = 80;
            nw = 16;

            permutation = new int[]         {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1};
            reversePermutation = new int[]  {0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7};
            rotationConst = new int[][]{
                    {24, 38, 33, 5, 41, 16, 31, 9},
                    {13, 19, 4, 20, 9, 34, 44, 48},
                    {8, 10, 51, 48, 37, 56, 47, 35},
                    {47, 55, 13, 41, 31, 51, 46, 52},
                    {8, 49, 34, 47, 12, 4, 19, 23},
                    {17, 18, 41, 28, 47, 53, 42, 31},
                    {22, 23, 59, 16, 44, 42, 44, 37},
                    {37, 52, 17, 25, 30, 41, 25, 20}
            };
        } else
            throw new CipherError("Invalid block size");

        if (tweak instanceof byte[]) tweakInit((byte[]) tweak);
        else if (tweak instanceof long[]) tweakInit((long[]) tweak);
        else if (tweak instanceof String) tweakInit((String) tweak);
        else throw new CipherError("Invalid type of tweak");

        this.tweak[2] = this.tweak[0] ^ this.tweak[1];

        if (key instanceof long[]) this.key = keyInit((long[]) key, blockSize / 8 / 8);
        else if (key instanceof byte[]) this.key = keyInit((byte[]) key, blockSize / 8 / 8);
        else throw new CipherError("Invalid type of key");

        subkey = new long[nr / 4 + 1][nw];
        subkeyInit();
    }


    private long[] keyInit(byte[] key, int length) {
        long[] thisKey = new long[length + 1];
        thisKey[thisKey.length - 1] = 0x1BD11BDAA9FC1A22L;

        long[] tmp = SupportingTools.bytesToLongs(key, length);
        System.arraycopy(tmp, 0, thisKey, 0, length);

        for (int i = 0; i < thisKey.length - 1; i++)
            thisKey[thisKey.length - 1] ^= thisKey[i];

        return thisKey;
    }

    private long[] keyInit(long[] key, int length) {
        long[] thisKey = new long[length + 1];
        System.arraycopy(key, 0, thisKey, 0, key.length);
        if (key.length < length)
            for (int i = key.length; i < length; i++)
                thisKey[i] = 0;

        thisKey[thisKey.length - 1] = 0x1BD11BDAA9FC1A22L;

        for (int i = 0; i < thisKey.length - 1; i++)
            thisKey[thisKey.length - 1] ^= thisKey[i];

        return thisKey;
    }


    private void subkeyInit() {
        for (int s = 0; s < nr / 4 + 1; s++) {
            for (int i = 0; i <= nw - 4; i++)
                subkey[s][i] = key[(s + i) % (nw + 1)];

            subkey[s][nw - 3] = key[(s + nw - 3) % (nw + 1)] + tweak[s % 3];
            subkey[s][nw - 2] = key[(s + nw - 2) % (nw + 1)] + tweak[(s + 1) % 3];
            subkey[s][nw - 1] = key[(s + nw - 1) % (nw + 1)] + s;
        }
    }


    private void tweakInit(String str) {
        byte[] bytes = str.getBytes();
        tweakInit(bytes);
    }

    private void tweakInit(byte[] bytes) {
        for (int i = 0; i < 16; i++) {
            tweak[i / 8] <<= 8;

            if (i < bytes.length) tweak[i / 8] |= bytes[i];
            else tweak[i / 8] |= 0;
        }
    }

    private void tweakInit(long[] tweak) {
        this.tweak[0] = tweak[0];
        this.tweak[1] = tweak[1];
    }


    public byte[] encrypt(byte[] text) {
        long[] longText = SupportingTools.bytesToLongs(text, nw);

        return SupportingTools.longsToBytes(encrypt(longText));
    }

    public long[] encrypt(long[] block) {
        for (int round = 0; round < nr; round++) {
            if (round % 4 == 0)
                for (int i = 0; i < nw; i++)
                    block[i] += subkey[round / 4][i];

            for (int i = 0; i < nw / 2; i++) {
                SupportingTools.TwoArgs args = mix(block[2 * i], block[2 * i + 1], round % 8, i);
                block[2 * i] = args.a;
                block[2 * i + 1] = args.b;
            }

            long[] tmp = new long[nw];
            for (int i = 0; i < nw; i++)
                tmp[i] = block[permutation[i]];
            System.arraycopy(tmp, 0, block, 0, nw);
        }

        for (int i = 0; i < nw; i++)
            block[i] += subkey[nr / 4][i];

        return block;
    }


    public byte[] decrypt(byte[] text) {
        long[] longText = SupportingTools.bytesToLongs(text, nw);

        return SupportingTools.longsToBytes(decrypt(longText));
    }

    public long[] decrypt(long[] block) {
        for (int round = nr; round > 0; round--) {
            if (round % 4 == 0)
                for (int i = 0; i < nw; i++)
                    block[i] -= subkey[round / 4][i];

            long[] tmp = new long[nw];
            for (int i = 0; i < nw; i++)
                tmp[i] = block[reversePermutation[i]];
            System.arraycopy(tmp, 0, block, 0, nw);

            for (int i = 0; i < nw / 2; i++) {
                SupportingTools.TwoArgs args = demix(block[2 * i], block[2 * i + 1], (round - 1) % 8, i);
                block[2 * i] = args.a;
                block[2 * i + 1] = args.b;
            }
        }

        for (int i = 0; i < nw; i++)
            block[i] -= subkey[0][i];

        return block;
    }

    public int getBlockSize() {
        return nw * 8;
    }
}
