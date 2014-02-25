package org.johanstenberg.aes;

import java.io.BufferedInputStream;
import java.io.InputStream;

/**
 * Main class for the AES 128-bit key encryption.
 * <p/>
 * I used this tutorial for the implementation details:
 * http://cboard.cprogramming.com/c-programming/87805-%5Btutorial%5D-implementing-advanced-encryption-standard.html
 * <p/>
 * Java bytes are signed so I work with chars instead.
 *
 * @author Johan Stenberg <jostenbe@kth.se>
 */
public class AES {

    /**
     * Encrypts the plaintext with the provided key and then
     * prints it.
     *
     * @param key       The key to be used.
     * @param plainText The plaintext to be encrypted.
     */
    private static void solve(char[] key, char[] plainText) {
        MathUtils.fillInitialStateMatrix(plainText);

        byte[] encryption = MathUtils.AES(key);
        try {
            System.out.write(encryption);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * Main method.
     *
     * @param args Not used.
     * @throws Throwable Not used.
     */
    public static void main(String... args) throws Throwable {
        InputStream bufferedInputStream = new BufferedInputStream(System.in);
        boolean hasKey = false;
        char[] key = new char[Constants.BLOCK_LENGTH];
        byte[] bytes;
        while (true) {
            bytes = new byte[Constants.BLOCK_LENGTH];
            int next = bufferedInputStream.read(bytes);
            if (next == -1) break;
            char[] input = MathUtils.byteArrayToCharArray(bytes);

            if (!hasKey) {
                for (int i = 0; i < input.length; ++i) {
                    key[i] = input[i];
                }
                hasKey = true;
            } else {
                solve(key, input);
            }
        }
    }
}
