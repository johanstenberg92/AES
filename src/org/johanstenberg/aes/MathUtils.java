package org.johanstenberg.aes;

/**
 * Math utility class for the AES 128-bit key encryption.
 *
 * @author Johan Stenberg <jostenbe@kth.se>
 */
public class MathUtils {

    /**
     * Static round key matrix.
     */
    private static char[][] roundKey = new char[Constants.BLOCK_LENGTH / 4][Constants.BLOCK_LENGTH / 4];

    /**
     * Static state matrix.
     */
    private static char[][] state = new char[Constants.BLOCK_LENGTH / 4][Constants.BLOCK_LENGTH / 4];


    /**
     * Static expanded key.
     */
    private static char[] expandedKey = new char[Constants.EXPANDED_KEY_SIZE];

    /**
     * Static mix column.
     */
    private static char[] mixColumn = new char[4];

    /**
     * Static mix column copy.
     */
    private static char[] mixColumnCopy = new char[4];

    /**
     * Static output byte array.
     */
    private static byte[] output = new byte[Constants.BLOCK_LENGTH];

    /**
     * Static chars array for converting byteToChars.
     */
    private static char[] charsFromBytes = new char[Constants.BLOCK_LENGTH];

    /**
     * Helper method for XOR:ing in Java.
     *
     * @param a First parameter.
     * @param b Second parameter.
     * @return a ^ b
     */
    private static char xor(char a, char b) {
        int xor = a ^ b;
        return (char) (0xff & xor);
    }

    public static void fillInitialStateMatrix(char[] bytes) {
        fillInitialMatrix(bytes, state, 0);
    }

    /**
     * Takes a char array and turns into a 2D matrix.
     *
     * @param bytes Char array representing the data.
     * @return A matrix representing the char array.
     */
    private static void fillInitialMatrix(char[] bytes, char[][] matrix, int from) {
        for (int i = 0; i < Constants.BLOCK_LENGTH; ++i) {
            int y = i % 4;
            int x = (i - y) / 4;
            matrix[y][x] = bytes[i + from];
        }
    }

    /**
     * XOR:s the state matrix with the round key matrix.
     *
     * @param state    Current cipher state matrix.
     * @param roundKey Current round key matrix.
     */
    private static void addRoundKey(char[][] state, char[][] roundKey) {
        for (int i = 0; i < Constants.BLOCK_LENGTH / 4; ++i) {
            for (int j = 0; j < Constants.BLOCK_LENGTH / 4; ++j) {
                state[i][j] = xor(state[i][j], roundKey[i][j]);
            }
        }
    }

    /**
     * Shifts each row in the matrix left, the first row is
     * shifted 0 steps, the second 1 step, the third 2 steps
     * and the fourth 3 steps.
     *
     * @param state Current cipher state matrix.
     */
    private static void shiftRows(char[][] state) {
        char temp;
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        temp = state[3][0];
        state[3][0] = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = temp;
    }

    /**
     * Swaps each byte in the state matrix with
     * the sbox value.
     *
     * @param state Current cipher state matrix.
     */
    private static void subBytes(char[][] state) {
        state[0][0] = Constants.getSboxValue(state[0][0]);
        state[0][1] = Constants.getSboxValue(state[0][1]);
        state[0][2] = Constants.getSboxValue(state[0][2]);
        state[0][3] = Constants.getSboxValue(state[0][3]);

        state[1][0] = Constants.getSboxValue(state[1][0]);
        state[1][1] = Constants.getSboxValue(state[1][1]);
        state[1][2] = Constants.getSboxValue(state[1][2]);
        state[1][3] = Constants.getSboxValue(state[1][3]);

        state[2][0] = Constants.getSboxValue(state[2][0]);
        state[2][1] = Constants.getSboxValue(state[2][1]);
        state[2][2] = Constants.getSboxValue(state[2][2]);
        state[2][3] = Constants.getSboxValue(state[2][3]);

        state[3][0] = Constants.getSboxValue(state[3][0]);
        state[3][1] = Constants.getSboxValue(state[3][1]);
        state[3][2] = Constants.getSboxValue(state[3][2]);
        state[3][3] = Constants.getSboxValue(state[3][3]);
    }

    /**
     * Method used internally in the mixColumn method. Applies
     * Galois Multiplication between the two input parameters
     * and returns the result.
     * <p/>
     * Uses predefined tables for quicker execution.
     *
     * @param a First parameter.
     * @param b Second parameter.
     * @return The resulting byte represented as a char.
     */
    public static char galoisMultiplication(char a, char b) {
        if (a == 0 || b == 0) return 0;
        char s;
        s = (char) ((int) Constants.getLTableValue((int) a) + (int) Constants.getLTableValue((int) b));
        s %= 255;
        s = Constants.getATableValue((int) s);

        return s;
    }

    /**
     * This method mixes each column of the state matrix.
     * Each column is multiplied with a matrix.
     *
     * @param state Current cipher state matrix.
     */
    private static void mixColumns(char[][] state) {
        int n = Constants.BLOCK_LENGTH / 4;
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                mixColumn[j] = state[j][i];
            }

            mixColumn(mixColumn);

            for (int j = 0; j < n; ++j) {
                state[j][i] = mixColumn[j];
            }
        }
    }

    /**
     * The AES round.
     * <p/>
     * Applies first a swap of matrix cells from the state, taken from the
     * sbox values above.
     * <p/>
     * Secondly, the rows are shifted around, the first row shifts 0 steps
     * to the left, the second 1 step, the third 2 steps and the third four
     * steps.
     * <p/>
     * After that each column is mixed, see the mixColumns function documentation
     * for more information.
     * <p/>
     * Finally the round key matrix is XOR:ed with the state matrix.
     *
     * @param state    Current cipher state matrix.
     * @param roundKey Current round key matrix.
     */
    private static void AESRound(char[][] state, char[][] roundKey) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKey);
    }

    /**
     * Creates the round key matrix from the expanded key. Only uses
     * the first 16 bytes of the expanded key.
     *
     * @param expandedKey Expanded key to be used.
     * @return The round key matrix of the expanded key's first 16 bytes.
     */
    private static void createRoundKey(char[] expandedKey, int from) {
        fillInitialMatrix(expandedKey, roundKey, from);
    }

    /**
     * Mixes the given column by multiplying it with a matrix.
     * <p/>
     * The matrix used is:
     * 2 3 1 1
     * 1 2 3 1
     * 1 1 2 3
     * 3 1 1 2
     *
     * @param column Column to be mixed.
     */
    private static void mixColumn(char[] column) {
        int n = Constants.BLOCK_LENGTH / 4;

        for (int i = 0; i < n; i++) {
            mixColumnCopy[i] = column[i];
        }

        column[0] = xor(xor(xor(galoisMultiplication(mixColumnCopy[0], (char) 2),
                galoisMultiplication(mixColumnCopy[3], (char) 1)),
                galoisMultiplication(mixColumnCopy[2], (char) 1)),
                galoisMultiplication(mixColumnCopy[1], (char) 3));

        column[1] = xor(xor(xor(galoisMultiplication(mixColumnCopy[1], (char) 2),
                galoisMultiplication(mixColumnCopy[0], (char) 1)),
                galoisMultiplication(mixColumnCopy[3], (char) 1)),
                galoisMultiplication(mixColumnCopy[2], (char) 3));

        column[2] = xor(xor(xor(galoisMultiplication(mixColumnCopy[2], (char) 2),
                galoisMultiplication(mixColumnCopy[1], (char) 1)),
                galoisMultiplication(mixColumnCopy[0], (char) 1)),
                galoisMultiplication(mixColumnCopy[3], (char) 3));

        column[3] = xor(xor(xor(galoisMultiplication(mixColumnCopy[3], (char) 2),
                galoisMultiplication(mixColumnCopy[2], (char) 1)),
                galoisMultiplication(mixColumnCopy[1], (char) 1)),
                galoisMultiplication(mixColumnCopy[0], (char) 3));
    }

    /**
     * Shifts the word 1 step to the left.
     *
     * @param word Word to be modified.
     */
    private static void rotate(char[] word) {
        char first = word[0];
        for (int i = 0; i < 3; ++i) {
            word[i] = word[i + 1];
        }

        word[3] = first;
    }

    /**
     * Applies the core rotation, sbox permutation and
     * XOR operation with the given RCON value.
     *
     * @param word  Word to be modified.
     * @param round The current round.
     */
    private static void applyCore(char[] word, int round) {
        rotate(word);
        for (int i = 0; i < 4; ++i) {
            word[i] = Constants.getSboxValue(word[i]);
        }

        word[0] = xor(word[0], Constants.getRCONValue((char) round));
    }

    /**
     * Expands the given key to 176 bytes instead of 16.
     *
     * @param key Key to be expanded.
     * @return The expanded 176 bytes key.
     */
    private static char[] keyExpansion(char[] key) {
        int n = Constants.BLOCK_LENGTH / 4;
        int currentSize = 0;
        int rconIteration = 1;
        char[] temp = new char[n];

        for (int i = 0; i < Constants.KEY_SIZE; ++i) {
            expandedKey[i] = key[i];
        }

        currentSize += Constants.KEY_SIZE;

        while (currentSize < Constants.EXPANDED_KEY_SIZE) {
            for (int i = 0; i < n; ++i) {
                temp[i] = expandedKey[(currentSize - n) + i];
            }

            if (currentSize % Constants.KEY_SIZE == 0) {
                applyCore(temp, rconIteration++);
            }

            for (int i = 0; i < n; ++i) {
                char expandedKeyFormer = expandedKey[currentSize - Constants.KEY_SIZE];
                char tempByte = temp[i];
                expandedKey[currentSize++] = xor(expandedKeyFormer, tempByte);
            }
        }

        return expandedKey;
    }

    /**
     * Converts an array of bytes to an array of chars.
     *
     * @param bytes Bytes to be converted.
     * @return The converted char array.
     */
    public static char[] byteArrayToCharArray(byte[] bytes) {
        for (int i = 0; i < charsFromBytes.length; ++i) {
            charsFromBytes[i] = (char) (bytes[i] < 0 ? bytes[i] + (1 << 8) : bytes[i]);
        }

        return charsFromBytes;
    }

    /**
     * Returns the byte array of the final AES encryption state matrix.
     *
     * @param finalState The final state of the AES encryption state matrix.
     */
    public static byte[] createEncryptionByteArray(char[][] finalState) {
        for (int i = 0; i < Constants.BLOCK_LENGTH; ++i) {
            int y = i % 4;
            int x = (i - y) / 4;
            output[i] = (byte) finalState[y][x];
        }

        return output;
    }

    /**
     * Applies a 10 round AES encryption for the state matrix, using the
     * supplied key. Returns the resulting cipher.
     *
     * @param key The key to be used in the encryption, must be 128 bits.
     * @return The encrypted byte array.
     */
    public static byte[] AES(char[] key) {
        char[] expandedKey = keyExpansion(key);

        createRoundKey(expandedKey, 0);
        addRoundKey(state, roundKey);

        for (int i = 1; i < Constants.ROUNDS; ++i) {
            createRoundKey(expandedKey, i * Constants.BLOCK_LENGTH);
            AESRound(state, roundKey);
        }

        createRoundKey(expandedKey, Constants.ROUNDS * Constants.BLOCK_LENGTH);
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKey);

        return createEncryptionByteArray(state);
    }
}
