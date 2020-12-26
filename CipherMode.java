public class CipherMode {
    // Произвольная функция изменения счётчика в режиме CTR
    private static long upgradeCounter(long l) {
        for (int i = 0; i < 64; i++) {
            int tmp = (int) (l >> 5) & 1;
            tmp ^= (int) (l >>> 10) & 1;
            tmp ^= (int) (l >>> 25) & 1;
            tmp ^= (int) (l >>> 45) & 1;

            l >>>= 1;
            l |= ((long) tmp << 63);
        }

        return l ^ 0x1BD11BDAA9FC1A22L;
    }

    public static byte[] ctr(ThreeFish cipher, String controlKey, byte[] buf, long IV_CTR) {
        if (!controlKey.equals("encrypt") && !controlKey.equals("decrypt"))
            throw new ThreeFish.CipherError("Unknown key. Valid values: \"encryption\" or \"decryption\"");

        int blockSize = cipher.getBlockSize();
        // Кратная длина
        int multipleLength = (buf.length + blockSize - 1) / blockSize * blockSize;

        byte[] tempBuf = new byte[multipleLength];
        byte[] outputBlock;
        byte[] inputBlock = new byte[blockSize];
        System.arraycopy(buf, 0, tempBuf, 0, buf.length);

        for (int i = 0; i < multipleLength; i += blockSize) {
            System.arraycopy(tempBuf, i, inputBlock, 0, blockSize);
            outputBlock = cipher.encrypt(SupportingTools.longToBytes(IV_CTR));

            for (int j = 0; j < blockSize; j++) outputBlock[j] ^= inputBlock[j];
            IV_CTR = upgradeCounter(IV_CTR);
            System.arraycopy(outputBlock, 0, tempBuf, i, blockSize);
        }

        // Избавиться от мусора в конце
        if (controlKey.equals("decrypt")) {
            multipleLength--;
            while (tempBuf[multipleLength] == 0) multipleLength--;
            multipleLength++;
        }
        buf = new byte[multipleLength];
        System.arraycopy(tempBuf, 0, buf, 0, multipleLength);

        return buf;
    }

    public static byte[] ecb(ThreeFish cipher, String controlKey, byte[] buf) {
        if (!controlKey.equals("encrypt") && !controlKey.equals("decrypt"))
            throw new ThreeFish.CipherError("Unknown key. Valid values: \"encryption\" or \"decryption\"");

        int blockSize = cipher.getBlockSize();
        // Кратная длина
        int multipleLength = (buf.length + blockSize - 1) / blockSize * blockSize;

        byte[] tempBuf = new byte[multipleLength];
        byte[] block = new byte[blockSize];
        System.arraycopy(buf, 0, tempBuf, 0, buf.length);

        if (controlKey.equals("encrypt"))
            for (int i = 0; i < multipleLength; i += blockSize) {
                System.arraycopy(tempBuf, i, block, 0, blockSize);
                block = cipher.encrypt(block);
                System.arraycopy(block, 0, tempBuf, i, blockSize);
            }
        else // controlKey.equals("decrypt")
            for (int i = 0; i < multipleLength; i += blockSize) {
                System.arraycopy(tempBuf, i, block, 0, blockSize);
                block = cipher.decrypt(block);
                System.arraycopy(block, 0, tempBuf, i, blockSize);
            }

        // Избавиться от мусора в конце
        if (controlKey.equals("decrypt")) {
            multipleLength--;
            while (tempBuf[multipleLength] == 0) multipleLength--;
            multipleLength++;
        }
        buf = new byte[multipleLength];
        System.arraycopy(tempBuf, 0, buf, 0, multipleLength);

        return buf;
    }
}
