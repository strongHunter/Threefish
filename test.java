import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class test {
    // 0-key-file, 1-file, 2-controlKey, 3-blockSize, 4-mode
    public static void main(String[] args) {
        if (SupportingTools.checkControlSums()) System.out.println("Контрольные значения совпадают");
        else System.out.println("Алгоритм работает некорректно");

        if (args.length < 5)
            throw new ThreeFish.CipherError("Недостаточно аргументов при запуске.\n0-key-file, 1-file," +
                    "2-controlKey,3-blockSize, 4-mode\nГде controlKey - encrypt/decrypt, blockSize - 256/512/1024, " +
                    "mode - ctr/ecb key-file и file - имена файлов с ключом и текстом соответственно");

        String keyFileName = args[0];
        String fileName = args[1];
        String controlKey = args[2];
        int blockSize = Integer.parseInt(args[3]);
        String mode = args[4];

        byte[] buf;
        byte[] key;
        byte[] tweak = new byte[16];
        ThreeFish cipher;

        try {
            FileInputStream fis = new FileInputStream(keyFileName);
            key = new byte[fis.available()];
            if (fis.read(key) == -1) throw new ThreeFish.CipherError("Could not read the file " + keyFileName);
            fis.close();
        } catch (IOException e) {
            System.out.println("Ошибка открытия файла-ключа " + e);
            return;
        }

        try {
            FileInputStream fis = new FileInputStream(fileName);
            buf = new byte[fis.available()];
            if (fis.read(buf) == -1) throw new ThreeFish.CipherError("Could not read the file " + fileName);
            fis.close();
        } catch (IOException e) {
            System.out.println("Ошибка открытия файла " + e);
            return;
        }


        if (controlKey.equalsIgnoreCase("encrypt")) {
            for (int i = 0; i < 16; i++)
                tweak[i] = (byte) (Math.random() * 0x7f);

            cipher = new ThreeFish(key, tweak, blockSize);

            if (mode.equalsIgnoreCase("ctr")) {
                long IV = (long) (Math.random() * 0x7fffffffffffffffL);
                buf = CipherMode.ctr(cipher, "encrypt", buf, IV);
                cipher = null;
                byte[] newBuf = new byte[buf.length + 16 + 8];
                System.arraycopy(tweak, 0, newBuf, 0, 16);
                System.arraycopy(SupportingTools.longToBytes(IV), 0, newBuf, 16, 8);
                System.arraycopy(buf, 0, newBuf, 16 + 8, buf.length);
                buf = newBuf;
            } else if (mode.equalsIgnoreCase("ecb")) {
                buf = CipherMode.ecb(cipher, "encrypt", buf);
                cipher = null;
                byte[] newBuf = new byte[buf.length + 16];
                System.arraycopy(tweak, 0, newBuf, 0, 16);
                System.arraycopy(buf, 0, newBuf, 16, buf.length);
                buf = newBuf;
            } else throw new ThreeFish.CipherError("Unknown encryption mode");
        }
        else if (controlKey.equalsIgnoreCase("decrypt")) {
            System.arraycopy(buf, 0, tweak, 0, 16);
            cipher = new ThreeFish(key, tweak, blockSize);

            if (mode.equalsIgnoreCase("ctr")) {
                byte[] _IV_ = new byte[8];
                System.arraycopy(buf, 16, _IV_, 0, 8);
                long IV = SupportingTools.bytesToLong(_IV_);
                byte[] newBuf = new byte[buf.length - 16 - 8];
                System.arraycopy(buf, 16 + 8, newBuf, 0, buf.length - 16 - 8);
                buf = CipherMode.ctr(cipher, "decrypt", newBuf, IV);
                cipher = null;
            } else if (mode.equalsIgnoreCase("ecb")) {
                byte[] newBuf = new byte[buf.length - 16];
                System.arraycopy(buf, 16 , newBuf, 0, buf.length - 16);
                buf = CipherMode.ecb(cipher, "decrypt", newBuf);
                cipher = null;
            } else throw new ThreeFish.CipherError("Unknown encryption mode");
        }
        else throw new ThreeFish.CipherError("Unknown key at arg 1. Valid values: \"encryption\" or \"decryption\"");

        try {
            StringBuilder outputFileName = new StringBuilder();
            if (!fileName.contains(mode.toUpperCase())) outputFileName.append(fileName).
                    insert(fileName.lastIndexOf('.'), '_' + controlKey.toLowerCase() + mode.toUpperCase());
            else outputFileName.append(fileName).replace(fileName.indexOf(mode.toUpperCase()) - 7,
                        fileName.indexOf(mode.toUpperCase()), controlKey.toLowerCase());


            FileOutputStream fos = new FileOutputStream(outputFileName.toString());
            fos.write(buf, 0, buf.length);
            fos.close();
        } catch (IOException e) {
            System.out.println("Ошибка при создании файла " + e);
        }
    }
}
