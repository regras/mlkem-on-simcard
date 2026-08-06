package org.example;

import javacard.framework.*;

import javacard.security.RandomData;


public class MLKEMApplet extends Applet {
    public final static int paramsN = 256;  //polynomial size
    public final static int paramsQ = 3329; //modulus Q
    public final static int paramsQinv = 62209; //inverse of the modulus Q
    public final static int paramsSymBytes = 32;
    public final static int paramsPolyBytes = 384;
    public final static int paramsETAK512 = 3;
    public final static int paramsETAK768K1024 = 2;
    public final static int paramsPolyvecBytesK512 = 2 * paramsPolyBytes;
    public final static int paramsPolyvecBytesK768 = 3 * paramsPolyBytes;
    public final static int paramsPolyvecBytesK1024 = 4 * paramsPolyBytes;
    public final static int paramsPolyCompressedBytesK512 = 128;
    public final static int paramsPolyCompressedBytesK768 = 128;
    public final static int paramsPolyCompressedBytesK1024 = 160;
    public final static int paramsPolyvecCompressedBytesK512 = 2 * 320;
    public final static int paramsPolyvecCompressedBytesK768 = 3 * 320;
    public final static int paramsPolyvecCompressedBytesK1024 = 4 * 352;
    private static final short paramsSHAKE128_Rate = 168;
    private static final short paramsSHAKE256_Rate = 136;
    private static final short paramsSHA3_256_Rate = 136;
    private static final short paramsSHA3_512_Rate = 72;
    private static final byte SHAKEpadding =  (byte) 0x1F;
    private static final byte SHA3padding = (byte) 0x06;


    // MLKEM512SKBytes is a constant representing the byte length of private keys in Kyber-512 (dk + eh + ekh + 32)
    public final static int MLKEM512SKBytes = paramsPolyvecBytesK512 + (paramsPolyvecBytesK512 + paramsSymBytes) + 32 + paramsSymBytes;

    // MLKEM768SKBytes is a constant representing the byte length of private keys in Kyber-768 (dk + eh + ekh + 32)
    public final static int MLKEM768SKBytes = paramsPolyvecBytesK768 + (paramsPolyvecBytesK768 + paramsSymBytes) + 32 + paramsSymBytes;

    // MLKEM1024SKBytes is a constant representing the byte length of private keys in Kyber-1024 (dk + eh + ekh + 32)
    public final static int MLKEM1024SKBytes = paramsPolyvecBytesK1024 + (paramsPolyvecBytesK1024 + paramsSymBytes) + 32 + paramsSymBytes;

    // MLKEM512PKBytes is a constant representing the byte length of public keys in Kyber-512
    public final static int MLKEM512PKBytes = paramsPolyvecBytesK512 + paramsSymBytes;

    // MLKEM768PKBytes is a constant representing the byte length of public keys in Kyber-768
    public final static int MLKEM768PKBytes = paramsPolyvecBytesK768 + paramsSymBytes;

    // MLKEM1024PKBytes is a constant representing the byte length of public keys in Kyber-1024
    public final static int MLKEM1024PKBytes = paramsPolyvecBytesK1024 + paramsSymBytes;

    // MLKEM512CTBytes is a constant representing the byte length of ciphertexts in Kyber-512
    public final static int MLKEM512CTBytes = paramsPolyvecCompressedBytesK512 + paramsPolyCompressedBytesK512;

    // MLKEM768CTBytes is a constant representing the byte length of ciphertexts in Kyber-768
    public final static int MLKEM768CTBytes = paramsPolyvecCompressedBytesK768 + paramsPolyCompressedBytesK768;

    // MLKEM1024CTBytes is a constant representing the byte length of ciphertexts in Kyber-1024
    public final static int MLKEM1024CTBytes = paramsPolyvecCompressedBytesK1024 + paramsPolyCompressedBytesK1024;

    // MLKEMSSBytes is a constant representing the byte length of shared secrets in Kyber
    public final static short MLKEMSSBytes = 32;

    //------------------------- SHAKE and SHA3 constants -------------------------------
    public static final short[] rhoPositions = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };
    public static final short[] piPositions = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };
    public static final byte[] rc0 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};
    public static final byte[] rc1 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x82};
    public static final byte[] rc2 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x8A};
    public static final byte[] rc3 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x00};
    public static final byte[] rc4 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x8B};
    public static final byte[] rc5 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x01};
    public static final byte[] rc6 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x81};
    public static final byte[] rc7 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x09};
    public static final byte[] rc8 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x8A};
    public static final byte[] rc9 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x88};
    public static final byte[] rc10 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x09};
    public static final byte[] rc11 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x0A};
    public static final byte[] rc12 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x8B};
    public static final byte[] rc13 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x8B};
    public static final byte[] rc14 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x89};
    public static final byte[] rc15 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x03};
    public static final byte[] rc16 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x02};
    public static final byte[] rc17 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80};
    public static final byte[] rc18 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x0A};
    public static final byte[] rc19 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x0A};
    public static final byte[] rc20 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x81};
    public static final byte[] rc21 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x80};
    public static final byte[] rc22 = {(byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x01};
    public static final byte[] rc23 = {(byte) 0x80, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x08};

    public static byte[] state;
    public static byte[] B;
    public static byte[] C;
    public static byte[] D;
    public static byte[] buff;
    public static byte[] buff1;
    public static byte[] buff2;
    public static byte[] buff3;
    public static short[] sb;
    public static boolean[] bb;

    private static short pos;           // Posição atual no bloco
    private static boolean isSqueezing; // Trava de segurança entre Absorb e Squeeze

    /**
     * Creates a transient short array that is cleared on system reset
     *
     * @param length the size of the array
     * @return a transient short array
     */
    private static short[] transientShortArray(int length) {
        return JCSystem.makeTransientShortArray((short) length, JCSystem.CLEAR_ON_RESET);
    }

    /**
     * Creates a transient byte array that is cleared on system reset
     *
     * @param length the size of the array
     * @return a transient byte array
     */
    private static byte[] transientByteArray(int length) {
        return JCSystem.makeTransientByteArray((short) length, JCSystem.CLEAR_ON_RESET);
    }

    //-------------------------------NTT constants------------------------------------
    static final short[] ZETAS = new short[]{
            2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
            2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
            732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
            1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
            107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
            430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
            1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
            418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
            1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
            478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628};


    static final short[] ZETAS_INV = new short[]{
            1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
            1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
            1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
            1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
            3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
            1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
            1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
            2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
            829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
            3127, 3042, 1907, 1836, 1517, 359, 758, 1441};

    //---------------------- Buffers used during the algorithm ---------------------
    protected static short[] bufNoise;
    protected static short[] bufMatrix;
    protected static short[] bufPolyTemp;
    private static byte[] hashBuffer;
    private static byte[] seedBuf;
    private static byte[] secretKey;
    //    static byte[] packedEK;
    private static byte[] packedDK;
    private static RandomData sr;
    private static byte[] message;
    protected static byte[] bufC;
    protected static byte[] bufCRed;
    public static byte klevel;

    public MLKEMApplet(short level) {
        // SHAKE allocation buffers
        state = JCSystem.makeTransientByteArray((short) 200, JCSystem.CLEAR_ON_DESELECT);
        B = JCSystem.makeTransientByteArray((short) 40, JCSystem.CLEAR_ON_DESELECT);
        C = JCSystem.makeTransientByteArray((short) 40, JCSystem.CLEAR_ON_DESELECT);
        D = JCSystem.makeTransientByteArray((short) 40, JCSystem.CLEAR_ON_DESELECT);
        buff = JCSystem.makeTransientByteArray((short) 10, JCSystem.CLEAR_ON_DESELECT);
        buff1 = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        buff2 = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        buff3 = JCSystem.makeTransientByteArray((short) 40, JCSystem.CLEAR_ON_DESELECT);
        sb = JCSystem.makeTransientShortArray((short) 10, JCSystem.CLEAR_ON_DESELECT);
        bb = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

        // Buffer allocation
        bufNoise = transientShortArray(paramsN);
        bufMatrix = transientShortArray(paramsN);
        bufPolyTemp = transientShortArray(paramsN);
        hashBuffer = transientByteArray(672);
        seedBuf = transientByteArray(64);
//        packedEK = transientByteArray(1184);
        sr = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        secretKey = transientByteArray(MLKEMSSBytes);
        message = transientByteArray(32);

        if (level == 1 || level == 2) {
            // ML-KEM-512
            packedDK = new byte[MLKEM512SKBytes];
            bufC = transientByteArray(MLKEM512CTBytes);
            bufCRed = transientByteArray(MLKEM512CTBytes);
        }
        if (level == 3) {
            // ML-KEM-768
            packedDK = new byte[MLKEM768SKBytes];
            bufC = transientByteArray(MLKEM768CTBytes);
            bufCRed = transientByteArray(MLKEM768CTBytes);
        }
        if (level == 5) {
            // ML-KEM-1024
            packedDK = new byte[MLKEM1024SKBytes];
            bufC = transientByteArray(MLKEM1024CTBytes);
            bufCRed = transientByteArray(MLKEM1024CTBytes);
        }
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Initialize the applet
        short offset = bOffset;

        // Skips id instance
        byte iidLength = bArray[offset];
        offset = (short) (offset + iidLength + 1);

        // Skips private control info
        byte privLength = bArray[offset];
        offset = (short) (offset + privLength + 1);

        // Reads the length of the applet data (appData) from the installation parameters
        byte appDataLength = bArray[offset];
        offset = (short) (offset + 1);

        // Defines a secure default level (maximum security) in case the user does not provide any installation parameters
        byte kLevel = (byte) 5;

        // If the user passes a parameter, the level of security is read
        if (appDataLength > 0) {
            kLevel = bArray[offset]; // Gets the security level (1,2, 3 or 5)

            // Basic security check
            if (kLevel < 1 || kLevel > 5 || kLevel == 3) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }

        // Passes the security level to the constructor
        new MLKEMApplet(kLevel).register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public final static byte INS_GENERATE_KEYS = (byte) 0x01; // generate the pair of keys
    public final static byte INS_ENCAPSULATE   = (byte) 0x02; // encapsulate and generate the shared secret and cipher text
    public final static byte INS_DECAPSULATE   = (byte) 0x03; // decapsulate the cipher text and extract the shared secret
    public final static byte INS_GEN_VEC      = (byte) 0x04; // generate a polynomial of a vector for testing
    public final static byte INS_GEN_MAT      = (byte) 0x05; // generate a polynomial of a matrix for testing
    public final static byte INS_MUL_POL      = (byte) 0x06; // multiply two polynomials for testing
    public final static byte INS_NTT      = (byte) 0x07; // NTT of a polynomial for testing
    public final static byte INS_SEND_PK       = (byte) 0x20; // sends the public key

    /**
     * Processes incoming APDU commands and routes them to appropriate ML-KEM operations
     *
     * @param apdu the APDU command/response object
     */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();

        // Verifica a Classe (CLA) do comando (Usaremos 0x80 como padrão)
        if (buffer[ISO7816.OFFSET_CLA] != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_GENERATE_KEYS:
                switch (klevel) {
                    case 1, 2:
                        generateKeys512();
                        break;
                    case 3:
                        generateKeys768();
                        break;
                    case 5:
                        generateKeys1024();
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                break;

            case INS_ENCAPSULATE:
                encapsulation1024();

                // Copia do cofre (packedDK) para o buffer de saída do APDU
                Util.arrayCopyNonAtomic(secretKey, (short) 0, buffer, (short) 0, MLKEMSSBytes);

                // 3. Envia os dados para o computador (Terminal)
                apdu.setOutgoingAndSend((short) 0, MLKEMSSBytes);
                break;

            case INS_DECAPSULATE:
                decapsulation1024();


                Util.arrayCopyNonAtomic(secretKey, (short) 0, buffer, (short) 0, MLKEMSSBytes);

                // 3. Envia os dados para o computador (Terminal)
                apdu.setOutgoingAndSend((short) 0, MLKEMSSBytes);
                break;

            case INS_SEND_PK:
                switch (klevel) {
                    case 1, 2:
                        bytesMissing = MLKEM512PKBytes;
                        offset = MLKEM512SKBytes;
                        break;
                    case 3:
                        bytesMissing = MLKEM768PKBytes;
                        offset = MLKEM768SKBytes;
                        break;
                    case 5:
                        bytesMissing = MLKEM1024PKBytes;
                        offset = MLKEM1024SKBytes;
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                sendExtendedData(apdu, packedDK);

                break;

            case INS_GEN_MAT:
                generateMatrix(seedBuf, false, 2, (short) 0, (short) 0, bufMatrix);

                break;

            case INS_GEN_VEC:
                getNoisePoly(seedBuf, (short) 32,(byte) 0,(short) 2, bufNoise, (short) 0);

                break;

            case INS_NTT:
                ntt(bufMatrix, (short) 0);

                break;

            case INS_MUL_POL:
                polyBaseMulMont(bufMatrix, 0, bufNoise, (short) 0, bufMatrix, (short) 0);

                break;



            default:
                // Se o PC enviar um comando que não existe (ex: 0x04)
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private short bytesMissing;
    private short offset;

    /**
     * Sends extended data via APDU in chunks to handle data larger than APDU buffer size
     *
     * @param apdu the APDU command/response object
     * @param array the data array to send
     */
    private void sendExtendedData(APDU apdu, byte[] array) {
        byte[] buffer = apdu.getBuffer();

        // Set the blocksize to be sent
        short blockSize = (short) 250;

        // If it is less than the block size, send the ret
        if (bytesMissing < blockSize) {
            blockSize = bytesMissing;
        }

        // Copy to the APDU buffer
        Util.arrayCopyNonAtomic(array, offset, buffer, (short) 0, blockSize);

        // Update values
        offset += blockSize;
        bytesMissing -= blockSize;

        // If there is data missing, send the current block and throw a controlled exception 61XX
        // When the PC receives 61XX, it will send a GET RESPONSE command to get the next block of data
        if (bytesMissing > 0) {
            // Envia os dados atuais e lança uma exceção controlada 61XX
            apdu.setOutgoingAndSend((short) 0, blockSize);
            ISOException.throwIt((short) (0x6100)); // 61 00 avisa que há mais dados
        } else {
            // Último bloco: envia e encerra normalmente com 90 00
            apdu.setOutgoingAndSend((short) 0, blockSize);
        }
    }

    /**
     * Called when the applet is deselected
     */
    public void deselect() {
    }

    /*
    -----------------------------------------------------------------------------------------

                            SHAKE and SHA3 functions (Keccak-f)

    -----------------------------------------------------------------------------------------
     */

    /**
     * Performs the Keccak-f permutation on the 1600-bit state
     * @param start the start for the rounds of this function
     */
    private static void permute(short start) {
        for (sb[0] = (short) 0; sb[0] < state.length; sb[0] += (short) 8) {
            littleEndian64(state, sb[0], state, sb[0], buff[0]);
        }

        for (sb[0] = start; sb[0] < (short) 24; sb[0]++) {

            // Step 1: Theta
            // C{byte 0 .. byte 7} = {X=0, Y=0} ^ {X=0, Y=1} ^ {X=0, Y=2} ^ {X=0, Y=3} ^ {X=0, Y=4}
            xor64(state, (short) 0, state, (short) 40, C, (short) 0);
            xor64(C, (short) 0, state, (short) 80, C, (short) 0);
            xor64(C, (short) 0, state, (short) 120, C, (short) 0);
            xor64(C, (short) 0, state, (short) 160, C, (short) 0);
            // C{byte 8 .. byte 15} = {X=1, Y=0} ^ {X=1, Y=1} ^ {X=1, Y=2} ^ {X=1, Y=3} ^ {X=1, Y=4}
            xor64(state, (short) 8, state, (short) 48, C, (short) 8);
            xor64(C, (short) 8, state, (short) 88, C, (short) 8);
            xor64(C, (short) 8, state, (short) 128, C, (short) 8);
            xor64(C, (short) 8, state, (short) 168, C, (short) 8);

            // C{byte 16 .. byte 23} = {X=2, Y=0} ^ {X=2, Y=1} ^ {X=2, Y=2} ^ {X=2, Y=3} ^ {X=2, Y=4}
            xor64(state, (short) 16, state, (short) 56, C, (short) 16);
            xor64(C, (short) 16, state, (short) 96, C, (short) 16);
            xor64(C, (short) 16, state, (short) 136, C, (short) 16);
            xor64(C, (short) 16, state, (short) 176, C, (short) 16);

            // C{byte 24 .. byte 31} = {X=3, Y=0} ^ {X=3, Y=1} ^ {X=3, Y=2} ^ {X=3, Y=3} ^ {X=3, Y=4}
            xor64(state, (short) 24, state, (short) 64, C, (short) 24);
            xor64(C, (short) 24, state, (short) 104, C, (short) 24);
            xor64(C, (short) 24, state, (short) 144, C, (short) 24);
            xor64(C, (short) 24, state, (short) 184, C, (short) 24);

            // C{byte 32 .. byte 39} = {X=4, Y=0} ^ {X=4, Y=1} ^ {X=4, Y=2} ^ {X=4, Y=3} ^ {X=4, Y=4}
            xor64(state, (short) 32, state, (short) 72, C, (short) 32);
            xor64(C, (short) 32, state, (short) 112, C, (short) 32);
            xor64(C, (short) 32, state, (short) 152, C, (short) 32);
            xor64(C, (short) 32, state, (short) 192, C, (short) 32);

            for (sb[1] = (short) 0; sb[1] < (short) 5; sb[1]++) {

                // D[i] = C[(i + 4) % 5].xor(leftRotate64(C[(i + 1) % 5], 1));
                // Portion 1: leftRotate64(C[(i + 1) % 5], 1)
                Util.arrayCopyNonAtomic(C, (short) ((sb[1] + 1) % 5 * 8), buff1, (short) 0, (short) 8);
                rotl64(buff1, (short) 0, (short) 1, buff, (short) 0, sb[3], sb[4], sb[5], sb[6]);

                // Portion 2: D[i] = C[(i + 4) % 5] ^ Portion 1;
                xor64(C, (short) ((sb[1] + 4) % 5 * 8), buff1, (short) 0, D, (short) (sb[1] * 8));

            }

            // state[i][j] = state[i][j].xor(D[i]);
            // X=0 ; Y=0,1,2,3,4;
            xor64(state, (short) 0, D, (short) 0, state, (short) 0);
            xor64(state, (short) 40, D, (short) 0, state, (short) 40);
            xor64(state, (short) 80, D, (short) 0, state, (short) 80);
            xor64(state, (short) 120, D, (short) 0, state, (short) 120);
            xor64(state, (short) 160, D, (short) 0, state, (short) 160);

            // X=1 ; Y=0,1,2,3,4;
            xor64(state, (short) 8, D, (short) 8, state, (short) 8);
            xor64(state, (short) 48, D, (short) 8, state, (short) 48);
            xor64(state, (short) 88, D, (short) 8, state, (short) 88);
            xor64(state, (short) 128, D, (short) 8, state, (short) 128);
            xor64(state, (short) 168, D, (short) 8, state, (short) 168);

            // X=2 ; Y=0,1,2,3,4;
            xor64(state, (short) 16, D, (short) 16, state, (short) 16);
            xor64(state, (short) 56, D, (short) 16, state, (short) 56);
            xor64(state, (short) 96, D, (short) 16, state, (short) 96);
            xor64(state, (short) 136, D, (short) 16, state, (short) 136);
            xor64(state, (short) 176, D, (short) 16, state, (short) 176);

            // X=3 ; Y=0,1,2,3,4;
            xor64(state, (short) 24, D, (short) 24, state, (short) 24);
            xor64(state, (short) 64, D, (short) 24, state, (short) 64);
            xor64(state, (short) 104, D, (short) 24, state, (short) 104);
            xor64(state, (short) 144, D, (short) 24, state, (short) 144);
            xor64(state, (short) 184, D, (short) 24, state, (short) 184);

            // X=4 ; Y=0,1,2,3,4;
            xor64(state, (short) 32, D, (short) 32, state, (short) 32);
            xor64(state, (short) 72, D, (short) 32, state, (short) 72);
            xor64(state, (short) 112, D, (short) 32, state, (short) 112);
            xor64(state, (short) 152, D, (short) 32, state, (short) 152);
            xor64(state, (short) 192, D, (short) 32, state, (short) 192);

            // Step 2: Rho and Pi
            Util.arrayCopyNonAtomic(state, (short) 8, buff2, (short) 0, (short) 8); // t = st[1];
            for (sb[1] = (short) 0; sb[1] < (short) 24; sb[1]++) { // for (i = 0; i < 24; i++) {
                Util.arrayCopyNonAtomic(state, (short) (piPositions[sb[1]] * 8), buff1, (short) 0, (short) 8);// bc[0] = st[keccakf_piln[i]];
                rotl64(buff2, (short) 0, rhoPositions[sb[1]], buff, (short) 0, sb[2], sb[3], sb[4], sb[5]); // rho <- ROTL64(t, keccakf_rotc[i]);
                Util.arrayCopyNonAtomic(buff2, (short) 0, state, (short) (piPositions[sb[1]] * 8), (short) 8);// st[keccakf_piln[i]] = rho;
                Util.arrayCopyNonAtomic(buff1, (short) 0, buff2, (short) 0, (short) 8);// t = bc[0];
            } // }

            // Step 3: Chi
            // #1
            Util.arrayCopyNonAtomic(state, (short) 0, B, (short) 0, (short) 40);
            Util.arrayCopyNonAtomic(state, (short) 0, buff3, (short) 0, (short) 40);

            // Unroll execute on Chi function B buffer
            flip64(B, (short) 8);
            and64(B, (short) 8, B, (short) 16, buff1, (short) 0);
            xor64(buff3, (short) 0, buff1, (short) 0, state, (short) 0);
            flip64(B, (short) 16);
            and64(B, (short) 16, B, (short) 24, buff1, (short) 0);
            xor64(buff3, (short) 8, buff1, (short) 0, state, (short) 8);
            flip64(B, (short) 24);
            and64(B, (short) 24, B, (short) 32, buff1, (short) 0);
            xor64(buff3, (short) 16, buff1, (short) 0, state, (short) 16);
            flip64(B, (short) 32);
            and64(B, (short) 32, B, (short) 0, buff1, (short) 0);
            xor64(buff3, (short) 24, buff1, (short) 0, state, (short) 24);
            flip64(B, (short) 0);
            and64(B, (short) 0, buff3, (short) 8, buff1, (short) 0);
            xor64(buff3, (short) 32, buff1, (short) 0, state, (short) 32);

            // #2
            Util.arrayCopyNonAtomic(state, (short) 40, B, (short) 0, (short) 40);
            Util.arrayCopyNonAtomic(state, (short) 40, buff3, (short) 0, (short) 40);
            flip64(B, (short) 8);
            and64(B, (short) 8, B, (short) 16, buff1, (short) 0);
            xor64(buff3, (short) 0, buff1, (short) 0, state, (short) 40);
            flip64(B, (short) 16);
            and64(B, (short) 16, B, (short) 24, buff1, (short) 0);
            xor64(buff3, (short) 8, buff1, (short) 0, state, (short) 48);
            flip64(B, (short) 24);
            and64(B, (short) 24, B, (short) 32, buff1, (short) 0);
            xor64(buff3, (short) 16, buff1, (short) 0, state, (short) 56);
            flip64(B, (short) 32);
            and64(B, (short) 32, B, (short) 0, buff1, (short) 0);
            xor64(buff3, (short) 24, buff1, (short) 0, state, (short) 64);
            flip64(B, (short) 0);
            and64(B, (short) 0, buff3, (short) 8, buff1, (short) 0);
            xor64(buff3, (short) 32, buff1, (short) 0, state, (short) 72);

            // #3
            Util.arrayCopyNonAtomic(state, (short) 80, B, (short) 0, (short) 40);
            Util.arrayCopyNonAtomic(state, (short) 80, buff3, (short) 0, (short) 40);
            flip64(B, (short) 8);
            and64(B, (short) 8, B, (short) 16, buff1, (short) 0);
            xor64(buff3, (short) 0, buff1, (short) 0, state, (short) 80);
            flip64(B, (short) 16);
            and64(B, (short) 16, B, (short) 24, buff1, (short) 0);
            xor64(buff3, (short) 8, buff1, (short) 0, state, (short) 88);
            flip64(B, (short) 24);
            and64(B, (short) 24, B, (short) 32, buff1, (short) 0);
            xor64(buff3, (short) 16, buff1, (short) 0, state, (short) 96);
            flip64(B, (short) 32);
            and64(B, (short) 32, B, (short) 0, buff1, (short) 0);
            xor64(buff3, (short) 24, buff1, (short) 0, state, (short) 104);
            flip64(B, (short) 0);
            and64(B, (short) 0, buff3, (short) 8, buff1, (short) 0);
            xor64(buff3, (short) 32, buff1, (short) 0, state, (short) 112);

            // #4
            Util.arrayCopyNonAtomic(state, (short) 120, B, (short) 0, (short) 40);
            Util.arrayCopyNonAtomic(state, (short) 120, buff3, (short) 0, (short) 40);
            flip64(B, (short) 8);
            and64(B, (short) 8, B, (short) 16, buff1, (short) 0);
            xor64(buff3, (short) 0, buff1, (short) 0, state, (short) 120);
            flip64(B, (short) 16);
            and64(B, (short) 16, B, (short) 24, buff1, (short) 0);
            xor64(buff3, (short) 8, buff1, (short) 0, state, (short) 128);
            flip64(B, (short) 24);
            and64(B, (short) 24, B, (short) 32, buff1, (short) 0);
            xor64(buff3, (short) 16, buff1, (short) 0, state, (short) 136);
            flip64(B, (short) 32);
            and64(B, (short) 32, B, (short) 0, buff1, (short) 0);
            xor64(buff3, (short) 24, buff1, (short) 0, state, (short) 144);
            flip64(B, (short) 0);
            and64(B, (short) 0, buff3, (short) 8, buff1, (short) 0);
            xor64(buff3, (short) 32, buff1, (short) 0, state, (short) 152);

            // #5
            Util.arrayCopyNonAtomic(state, (short) 160, B, (short) 0, (short) 40);
            Util.arrayCopyNonAtomic(state, (short) 160, buff3, (short) 0, (short) 40);
            flip64(B, (short) 8);
            and64(B, (short) 8, B, (short) 16, buff1, (short) 0);
            xor64(buff3, (short) 0, buff1, (short) 0, state, (short) 160);
            flip64(B, (short) 16);
            and64(B, (short) 16, B, (short) 24, buff1, (short) 0);
            xor64(buff3, (short) 8, buff1, (short) 0, state, (short) 168);
            flip64(B, (short) 24);
            and64(B, (short) 24, B, (short) 32, buff1, (short) 0);
            xor64(buff3, (short) 16, buff1, (short) 0, state, (short) 176);
            flip64(B, (short) 32);
            and64(B, (short) 32, B, (short) 0, buff1, (short) 0);
            xor64(buff3, (short) 24, buff1, (short) 0, state, (short) 184);
            flip64(B, (short) 0);
            and64(B, (short) 0, buff3, (short) 8, buff1, (short) 0);
            xor64(buff3, (short) 32, buff1, (short) 0, state, (short) 192);

            // Step 4: Iota
            xor64(state, (short) 0, getRoundConstant(sb[0]), (short) 0, state, (short) 0);
        }

        for (sb[0] = (short) 0; sb[0] < state.length; sb[0] += (short) 8) {
            littleEndian64(state, sb[0], state, sb[0], buff[0]);
        }
    }

    /**
     * Resets all Keccak buffers and state variables to their initial values
     */
    public static void reset() {
        Util.arrayFillNonAtomic(state, (short) 0, (short) state.length, (byte) 0x00);
        Util.arrayFillNonAtomic(B, (short) 0, (short) B.length, (byte) 0x00);
        Util.arrayFillNonAtomic(C, (short) 0, (short) C.length, (byte) 0x00);
        Util.arrayFillNonAtomic(D, (short) 0, (short) D.length, (byte) 0x00);
        Util.arrayFillNonAtomic(buff, (short) 0, (short) buff.length, (byte) 0x00);
        Util.arrayFillNonAtomic(buff1, (short) 0, (short) buff1.length, (byte) 0x00);
        Util.arrayFillNonAtomic(buff2, (short) 0, (short) buff2.length, (byte) 0x00);
        Util.arrayFillNonAtomic(buff3, (short) 0, (short) buff3.length, (byte) 0x00);
        sb[0] = (short) 0;
        sb[1] = (short) 0;
        sb[2] = (short) 0;
        sb[3] = (short) 0;
        sb[4] = (short) 0;
        sb[5] = (short) 0;
        sb[6] = (short) 0;
        sb[7] = (short) 0;
        sb[8] = (short) 0;
        sb[9] = (short) 0;
        bb[0] = false;

        pos = (short) 0;
        isSqueezing = false;
    }

    /**
     * Absorbs input data into the Keccak state with specified rate and padding
     *
     * @param inBuf the input buffer containing data to absorb
     * @param inOff the offset in the input buffer to start reading from
     * @param inLen the length of data to absorb in bytes
     * @param rate the rate of the sponge construction (in bytes)
     * @param padding the padding rule (either SHAKEpadding or SHA3padding)
     */
    public static void absorb(byte[] inBuf, short inOff, short inLen, short rate, byte padding) {
        if (isSqueezing) {
            reset();
        }

        // In case of using Turbo SHAKE, alter the first zero to 12
        short start = (padding == (byte) 0x1F) ? (short) 0 : (short) 0;

        short i = 0;
        while (i < inLen) {
            state[pos] = (byte) (state[pos] ^ inBuf[(short) (inOff + i)]);
            pos++;
            i++;

            if (pos == rate) {
                permute(start);
                pos = (short) 0;
            }
        }
    }

    /**
     * Finalizes the absorption phase by applying FIPS 202 padding to the state
     *
     * @param rate the rate of the sponge construction (in bytes)
     * @param padding the padding rule (either SHAKEpadding or SHA3padding)
     */
    private static void finalizeAbsorb(short rate, byte padding) {
        state[pos] = (byte) (state[pos] ^ padding);

        // Bit final indicando o fim do bloco
        state[(short) (rate - 1)] = (byte) (state[(short) (rate - 1)] ^ 0x80);

        short start = (padding == SHAKEpadding) ? (short) 0 : (short) 0;

        permute(start);
        pos = (short) 0;
        isSqueezing = true;
    }

    /**
     * Extracts output data from the sponge in the squeezing phase
     *
     * @param outBuf the output buffer to store the squeezed data
     * @param outOff the offset in the output buffer to start writing to
     * @param outLen the length of data to squeeze in bytes
     * @param rate the rate of the sponge construction (in bytes)
     * @param padding the padding rule (either SHAKEpadding or SHA3padding)
     */
    public static void squeeze(byte[] outBuf, short outOff, short outLen, short rate, byte padding) {
        if (!isSqueezing) {
            finalizeAbsorb(rate, padding);
        }
        short start = (padding == SHAKEpadding) ? (short) 0 : (short) 0;


        short i = 0;
        while (i < outLen) {
            if (pos == rate) {
                permute(start);
                pos = (short) 0;
            }
            outBuf[(short) (outOff + i)] = state[pos];
            pos++;
            i++;
        }
    }

    /**
     * Retrieves the round constant for a given round number in Keccak-f
     *
     * @param r the round number (0-23)
     * @return the round constant as a byte array for the specified round, or null if invalid
     */
    public static byte[] getRoundConstant(short r) {
        return switch (r) {
            case 0 -> rc0;
            case 1 -> rc1;
            case 2 -> rc2;
            case 3 -> rc3;
            case 4 -> rc4;
            case 5 -> rc5;
            case 6 -> rc6;
            case 7 -> rc7;
            case 8 -> rc8;
            case 9 -> rc9;
            case 10 -> rc10;
            case 11 -> rc11;
            case 12 -> rc12;
            case 13 -> rc13;
            case 14 -> rc14;
            case 15 -> rc15;
            case 16 -> rc16;
            case 17 -> rc17;
            case 18 -> rc18;
            case 19 -> rc19;
            case 20 -> rc20;
            case 21 -> rc21;
            case 22 -> rc22;
            case 23 -> rc23;
            default -> null;
        };
    }


    /**
     * Performs bitwise AND operation on two 64-bit values stored as byte arrays
     *
     * @param a the first 64-bit value as byte array
     * @param aOffset offset into array a
     * @param b the second 64-bit value as byte array
     * @param bOffset offset into array b
     * @param result the output byte array to store the result
     * @param offset offset into the result array
     */
    public static void and64(byte[] a, short aOffset, byte[] b, short bOffset, byte[] result, short offset) {
        result[offset] = (byte) (a[aOffset] & b[bOffset]);
        result[(short) (offset + 1)] = (byte) (a[(short) (aOffset + 1)] & b[(short) (bOffset + 1)]);
        result[(short) (offset + 2)] = (byte) (a[(short) (aOffset + 2)] & b[(short) (bOffset + 2)]);
        result[(short) (offset + 3)] = (byte) (a[(short) (aOffset + 3)] & b[(short) (bOffset + 3)]);
        result[(short) (offset + 4)] = (byte) (a[(short) (aOffset + 4)] & b[(short) (bOffset + 4)]);
        result[(short) (offset + 5)] = (byte) (a[(short) (aOffset + 5)] & b[(short) (bOffset + 5)]);
        result[(short) (offset + 6)] = (byte) (a[(short) (aOffset + 6)] & b[(short) (bOffset + 6)]);
        result[(short) (offset + 7)] = (byte) (a[(short) (aOffset + 7)] & b[(short) (bOffset + 7)]);
    }

    /**
     * Performs bitwise XOR operation on two 64-bit values stored as byte arrays
     *
     * @param a the first 64-bit value as byte array
     * @param aOffset offset into array a
     * @param b the second 64-bit value as byte array
     * @param bOffset offset into array b
     * @param result the output byte array to store the result
     * @param offset offset into the result array
     */
    public static void xor64(byte[] a, short aOffset, byte[] b, short bOffset, byte[] result, short offset) {
        result[offset] = (byte) (a[aOffset] ^ b[bOffset]);
        result[(short) (offset + 1)] = (byte) (a[(short) (aOffset + 1)] ^ b[(short) (bOffset + 1)]);
        result[(short) (offset + 2)] = (byte) (a[(short) (aOffset + 2)] ^ b[(short) (bOffset + 2)]);
        result[(short) (offset + 3)] = (byte) (a[(short) (aOffset + 3)] ^ b[(short) (bOffset + 3)]);
        result[(short) (offset + 4)] = (byte) (a[(short) (aOffset + 4)] ^ b[(short) (bOffset + 4)]);
        result[(short) (offset + 5)] = (byte) (a[(short) (aOffset + 5)] ^ b[(short) (bOffset + 5)]);
        result[(short) (offset + 6)] = (byte) (a[(short) (aOffset + 6)] ^ b[(short) (bOffset + 6)]);
        result[(short) (offset + 7)] = (byte) (a[(short) (aOffset + 7)] ^ b[(short) (bOffset + 7)]);
    }

    /**
     * Performs a left rotation on a 64-bit value stored as a byte array
     *
     * @param a the 64-bit value as byte array to rotate
     * @param offset offset into array a
     * @param amt the number of bits to rotate left
     * @param buff temporary buffer for intermediate calculations
     * @param buffOffset offset into the buffer
     * @param sBuff1 temporary variable for bit shift calculation
     * @param sBuff2 temporary variable for byte offset calculation
     * @param sBuff3 temporary variable for loop index
     * @param sBuff4 temporary variable for position calculation
     */
    public static void rotl64(byte[] a, short offset, short amt, byte[] buff,
                              short buffOffset, short sBuff1, short sBuff2, short sBuff3,
                              short sBuff4) {
        sBuff1 = (short) (amt % 8);
        sBuff2 = (short) (amt / 8);
        buff[buffOffset] = a[offset];
        for (sBuff3 = (short) 7; sBuff3 >= (short) 0; sBuff3--) {
            buff[(short) (buffOffset + 1)] = a[sBuff3];
            sBuff4 = (short) ((sBuff3 - sBuff2 + 8) % 8);
            buff[(short) (buffOffset + 2 + sBuff4)]
                    = (byte) ((byte) (buff[(short) (buffOffset + 1)] << sBuff1)
                    | (((byte) buff[buffOffset] & 0xff) >>> ((short) 8 - sBuff1)));
            buff[buffOffset] = buff[(short) (buffOffset + 1)];
        }

        Util.arrayCopyNonAtomic(buff, (short) (buffOffset + 2), a, offset, (short) 8);
    }

    /**
     * Performs bitwise NOT (flip) operation on a 64-bit value stored as a byte array
     *
     * @param a the 64-bit value as byte array to flip
     * @param offset offset into array a
     */
    public static void flip64(byte[] a, short offset) {
        a[offset] = (byte) ~a[offset];
        a[(short) (offset + 1)] = (byte) ~a[(short) (offset + 1)];
        a[(short) (offset + 2)] = (byte) ~a[(short) (offset + 2)];
        a[(short) (offset + 3)] = (byte) ~a[(short) (offset + 3)];
        a[(short) (offset + 4)] = (byte) ~a[(short) (offset + 4)];
        a[(short) (offset + 5)] = (byte) ~a[(short) (offset + 5)];
        a[(short) (offset + 6)] = (byte) ~a[(short) (offset + 6)];
        a[(short) (offset + 7)] = (byte) ~a[(short) (offset + 7)];
    }

    /**
     * Converts a 64-bit value between big-endian and little-endian byte order
     *
     * @param input the input byte array containing the 64-bit value
     * @param inOffset offset into the input array
     * @param output the output byte array to store the converted value
     * @param outOffset offset into the output array
     * @param buff temporary byte variable for swapping
     */
    public static void littleEndian64(byte[] input, short inOffset, byte[] output, short outOffset, byte buff) {
        // Swap pos 0 and 7
        buff = input[(short) (inOffset + 7)];
        output[(short) (outOffset + 7)] = input[inOffset];
        output[outOffset] = buff;

        // Swap pos 1 and 6
        buff = input[(short) (inOffset + 6)];
        output[(short) (outOffset + 6)] = input[(short) (inOffset + 1)];
        output[(short) (outOffset + 1)] = buff;

        // Swap pos 2 and 5
        buff = input[(short) (inOffset + 5)];
        output[(short) (outOffset + 5)] = input[(short) (inOffset + 2)];
        output[(short) (outOffset + 2)] = buff;

        // Swap pos 3 and 4
        buff = input[(short) (inOffset + 4)];
        output[(short) (outOffset + 4)] = input[(short) (inOffset + 3)];
        output[(short) (outOffset + 3)] = buff;
    }

    /*
    -----------------------------------------------------------------------------------------

                                        NTT Operations

    -----------------------------------------------------------------------------------------
     */

    /**
     * Multiply the given shorts and then run a Montgomery reduction
     *
     * @param a short type variable a
     * @param b short type variable b
     * @return the result of the multiplication and Montgomery reduction
     */
    static short modQMulMont(short a, short b) {
        return montgomeryReduce((a * b));
    }

    /**
     * Performs a Montgomery reduction
     *
     * @param a int type variable a
     * @return the result of the Montgomery reduction
     */
    static short montgomeryReduce(int a) {
        short u = (short) (a * paramsQinv);
        int t = (int) u * paramsQ;
        t = (a - t) >> 16;
        return (short) t;
    }

    /**
     * Performs a Barret reduction
     *
     * @param a short type variable a
     * @return the result of the Barret reduction
     */
    static short barrettReduce(short a) {
        short v = 20159;
        short t = (short) ((v * a) >> 26);
        t = (short) (t * paramsQ);
        return (short) (a - t);
    }

    /**
     * Perform an in-place number-theoretic transform (NTT)
     * <p>
     * Input is in standard order
     * <p>
     * Output is in bit-reversed order
     *
     * @param array the polynomial coefficients array
     * @param offset the starting offset in the array
     */
    static void ntt(short[] array, short offset) {
        short j, k = 1;
        for (short len = 128; len >= 2; len >>= 1) {
            for (short start = 0; start < 256; start = (short) (j + len)) {
                short zeta = ZETAS[k++];
                for (j = start; j < start + len; ++j) {
                    short idx1 = (short) (j + offset);
                    short idx2 = (short) (j + offset + len);
                    short t = array[idx1], u = modQMulMont(zeta, array[idx2]);
                    array[idx2] = (short) (t - u);
                    array[idx1] = (short) (t + u);
                }
            }
        }
    }

    /**
     * Perform an in-place inverse number-theoretic transform (NTT)
     * <p>
     * Input is in bit-reversed order
     * <p>
     * Output is in standard order
     *
     * @param array the polynomial coefficients array
     * @param offset the starting offset in the array
     */
    static void invNTT(short[] array, short offset) {
        short j, k = 0;
        for (short len = 2; len <= 128; len <<= 1) {
            for (short start = 0; start < 256; start = (short) (j + len)) {
                short zeta = ZETAS_INV[k++];
                for (j = start; j < start + len; ++j) {
                    short idx1 = (short) (j + offset);
                    short idx2 = (short) (j + offset + len);
                    short t = array[idx1], u = array[idx2];
                    array[idx1] = barrettReduce((short) (t + u));
                    array[idx2] = modQMulMont(zeta, (short) (t - u));
                }
            }
        }
        for (short i = 0; i < 256; ++i) {
            array[(short) (i + offset)] = modQMulMont(array[(short) (i + offset)], ZETAS_INV[127]);
        }
    }

    /**
     * Performs the multiplication of polynomials
     *
     * @param a0 short type variable a0
     * @param a1 short type variable a1
     * @param b0 short type variable b0
     * @param b1 short type variable b1
     * @param zeta precomputed roots of unity modulo a prime number q
     * @param array the polynomial coefficients array
     * @param roffset the starting offset in the array
     */
    public static void baseMultiplier(short a0, short a1, short b0, short b1, short zeta, short[] array, short roffset) {
        array[roffset] = modQMulMont(a1, b1);
        array[roffset] = modQMulMont(array[roffset], zeta);
        array[roffset] = (short) (array[roffset] + modQMulMont(a0, b0));
        array[(short) (roffset + 1)] = modQMulMont(a0, b1);
        array[(short) (roffset + 1)] = (short) (array[(short) (roffset + 1)] + modQMulMont(a1, b0));
    }

    /*
    -----------------------------------------------------------------------------------------

                                     Polynomial Operations

    -----------------------------------------------------------------------------------------
     */

    /**
     * Performs forward number-theoretic transform (NTT) on a polynomial with reduction
     *
     * @param array the polynomial coefficients array
     * @param offset the starting offset in the array
     */
    static void polyNTT(short[] array, short offset) {
        ntt(array, offset);
        reduce(array, offset);
    }

    /**
     * Performs inverse number-theoretic transform (NTT) on a polynomial
     *
     * @param array the polynomial coefficients array in bit-reversed order
     * @param offset the starting offset in the array
     */
    static void polyInverseNttToMont(short[] array, short offset) {
        invNTT(array, offset);
    }

    /**
     * Applies Barrett reduction to all coefficients of a polynomial
     *
     * @param array the polynomial coefficients array
     * @param offset the starting offset in the array
     */
    static void reduce(short[] array, short offset) {
        for (short i = offset; i < paramsN + offset; i++) {
            array[i] = barrettReduce(array[i]);
        }
    }

    /**
     * Performs lossy compression and serialization of a polynomial with offset parameters
     *
     * @param polyA the polynomial coefficients array
     * @param offset the starting offset in the polynomial array
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param result the output buffer for compressed polynomial bytes
     * @param roffset the starting offset in the output buffer
     * @param t temporary byte array for intermediate calculations
     */
    public static void compressPoly(short[] polyA, short offset, int paramsK, byte[] result, short roffset, byte[] t) {
        polyConditionalSubQ(polyA, offset);
        short rr = roffset;
        switch (paramsK) {
            case 2:
            case 3:
                for (short i = 0; i < paramsN / 8; i++) {
                    for (short j = 0; j < 8; j++) {
                        t[j] = (byte) (((((polyA[(short) (offset + 8 * i + j)]) << 4) + (paramsQ / 2)) / (paramsQ)) & 15);
                    }
                    result[rr] = (byte) (t[0] | (t[1] << 4));
                    result[(short) (rr + 1)] = (byte) (t[2] | (t[3] << 4));
                    result[(short) (rr + 2)] = (byte) (t[4] | (t[5] << 4));
                    result[(short) (rr + 3)] = (byte) (t[6] | (t[7] << 4));
                    rr = (short) (rr + 4);
                }
                break;
            default:
                for (short i = 0; i < paramsN / 8; i++) {
                    for (short j = 0; j < 8; j++) {
                        //avoids KyberSlash2 attacks
                        int t_j = polyA[(short) (offset + 8 * i + j)];

                        t_j <<= 5;
                        t_j += 1664;
                        t_j *= 40318;
                        t_j >>= 27;
                        t_j &= 31;

                        t[j] = (byte) t_j;
                    }
                    result[rr] = (byte) (t[0] | (t[1] << 5));
                    result[(short) (rr + 1)] = (byte) ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                    result[(short) (rr + 2)] = (byte) ((t[3] >> 1) | (t[4] << 4));
                    result[(short) (rr + 3)] = (byte) ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                    result[(short) (rr + 4)] = (byte) ((t[6] >> 2) | (t[7] << 3));
                    rr = (short) (rr + 5);
                }
        }
    }

    /**
     * De-serializes and decompresses a polynomial from byte array
     * <p>
     * Compression is lossy so the resulting polynomial will not match the original polynomial
     *
     * @param a the compressed byte array
     * @param aoffset the starting offset in the byte array
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param result the output polynomial array
     * @param offset the starting offset in the output array
     * @param t temporary byte array for intermediate calculations
     */

    public static void decompressPoly(byte[] a, short aoffset, int paramsK, short[] result, short offset, byte[] t) {
        short aa = aoffset;
        switch (paramsK) {
            case 2:
            case 3:
                for (short i = 0; i < paramsN / 2; i++) {
                    result[(short) (offset + 2 * i)] = (short) (((((a[aa] & 0xFF) & 15) * paramsQ) + 8) >> 4);
                    result[(short) (offset + 2 * i + 1)] = (short) (((((a[aa] & 0xFF) >> 4) * paramsQ) + 8) >> 4);
                    aa = (short) (aa + 1);
                }
                break;
            default:
                for (short i = 0; i < paramsN / 8; i++) {
                    t[0] = (byte) ((a[aa] & 0xFF));
                    t[1] = (byte) ((((a[aa] & 0xFF) >> 5)) | ((a[(short) (aa + 1)] & 0xFF) << 3));
                    t[2] = (byte) ((a[(short) (aa + 1)] & 0xFF) >> 2);
                    t[3] = (byte) ((((a[(short) (aa + 1)] & 0xFF) >> 7)) | ((a[(short) (aa + 2)] & 0xFF) << 1));
                    t[4] = (byte) ((((a[(short) (aa + 2)] & 0xFF) >> 4)) | ((a[(short) (aa + 3)] & 0xFF) << 4));
                    t[5] = (byte) ((a[(short) (aa + 3)] & 0xFF) >> 1);
                    t[6] = (byte) ((((a[(short) (aa + 3)] & 0xFF) >> 6)) | ((a[(short) (aa + 4)] & 0xFF) << 2));
                    t[7] = ((byte) ((a[(short) (aa + 4)] & 0xFF) >> 3));
                    aa = (short) (aa + 5);
                    for (short j = 0; j < 8; j++) {
                        result[(short) (offset + 8 * i + j)] = (short) ((((t[j] & 31) * paramsQ) + 16) >> 5);
                    }
                }
        }
    }

    /**
     * Serializes a polynomial into a byte array
     *
     * @param a the polynomial coefficients array
     * @param offset the starting offset in the polynomial array
     * @param result the output buffer for serialized bytes
     * @param rOffset the starting offset in the output buffer
     */
    public static void polyToBytes(short[] a, short offset, byte[] result, short rOffset) {
        short t0, t1;
        polyConditionalSubQ(a, offset);
        for (short i = 0; i < paramsN / 2; i++) {
            t0 = a[(short) (offset + 2 * i)];
            t1 = a[(short) (offset + 2 * i + 1)];
            result[(short) (rOffset + 3 * i)] = (byte) t0;
            result[(short) (rOffset + 3 * i + 1)] = (byte) ((t0 >> 8) | (t1 << 4));
            result[(short) (rOffset + 3 * i + 2)] = (byte) (t1 >> 4);
        }
    }

    /**
     * De-serializes a byte array into a polynomial with offset parameter
     *
     * @param a the input byte array
     * @param aOffset the starting offset in the input array
     * @param result the output polynomial array
     * @param offset the starting offset in the output polynomial array
     */
    public static void polyFromBytes(byte[] a, int aOffset, short[] result, short offset) {
        for (short i = 0; i < paramsN / 2; i++) {
            short index = (short) (aOffset + (3 * i));
            int a0 = a[index] & 0xFF;
            int a1 = a[(short) (index + 1)] & 0xFF;
            int a2 = a[(short) (index + 2)] & 0xFF;
            result[(short) (offset + 2 * i)] = (short) ((a0 | (a1 << 8)) & 0xFFF);
            result[(short) (offset + 2 * i + 1)] = (short) (((a1 >> 4) | (a2 << 4)) & 0xFFF);
        }
    }


    /**
     * Converts a 32-byte message to a polynomial using bit-expansion
     *
     * @param msg the 32-byte message array
     * @param result the output polynomial array
     * @param rOffset the starting offset in the output polynomial array
     */
    public static void polyFromData(byte[] msg, short[] result, short rOffset) {
        short mask;
        for (short i = 0; i < paramsN / 8; i++) {
            for (short j = 0; j < 8; j++) {
                mask = (short) (-1 * (short) (((msg[i] & 0xFF) >> j) & 1));
                result[(short) (rOffset + 8 * i + j)] = (short) (mask & (short) ((paramsQ + 1) / 2));
            }
        }
    }

    /**
     * Converts a polynomial to a 32-byte message with offset parameters
     *
     * @param a the polynomial coefficients array
     * @param offset the starting offset in the polynomial array
     * @param msg the output message byte array
     * @param msgOffset the starting offset in the output message array
     */
    public static void polyToMsg(short[] a, short offset, byte[] msg, short msgOffset) {
        int LOWER = paramsQ >>> 2;
        int UPPER = paramsQ - LOWER;
        polyConditionalSubQ(a, offset);
        for (short i = 0; i < paramsN / 8; i++) {
            msg[(short) (i + msgOffset)] = 0;
            for (short j = 0; j < 8; j++) {
                int c_j = a[(short) (offset + 8 * i + j)];
                int t = ((LOWER - c_j) & (c_j - UPPER)) >>> 31; //not constant time
                msg[(short) (i + msgOffset)] = (byte) (msg[(short) (i + msgOffset)] | (t << j));
            }
        }
    }

    /**
     * Generates a deterministic noise polynomial from a seed and nonce using CBD distribution
     * <p>
     * The polynomial output approximates a centered binomial distribution
     *
     * @param seed the seed byte array
     * @param seedOffset the starting offset in the seed array
     * @param nonce the nonce byte value
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param result the output polynomial array
     * @param rOffset the starting offset in the output polynomial array
     */
    public static void getNoisePoly(byte[] seed, short seedOffset, byte nonce, int paramsK, short[] result, short rOffset) {
        int l;
        if (paramsK == 2) {
            l = paramsETAK512 * paramsN / 4;
        } else {
            l = paramsETAK768K1024 * paramsN / 4;
        }

        generatePRFByteArray(l, seed, seedOffset, nonce, hashBuffer);
        generateCBDPoly(hashBuffer, paramsK, result, rOffset);
    }

    /**
     * Multiplies two polynomials in the NTT domain using Montgomery arithmetic with offset parameters
     *
     * @param polyA the first polynomial coefficients array
     * @param aOffset the starting offset in polyA
     * @param polyB the second polynomial coefficients array
     * @param bOffset the starting offset in polyB
     * @param result the output polynomial array
     * @param roffset the starting offset in the output array
     */
    public static void polyBaseMulMont(short[] polyA, int aOffset, short[] polyB, int bOffset, short[] result, short roffset) {
        for (short i = 0; i < paramsN / 4; i++) {
            baseMultiplier(
                    polyA[(short) (aOffset + 4 * i)], polyA[(short) (aOffset + 4 * i + 1)],
                    polyB[(short) (bOffset + 4 * i)], polyB[(short) (bOffset + 4 * i + 1)],
                    (ZETAS[(short) (64 + i)]), result, (short) (roffset + 4 * i)
            );
            baseMultiplier(
                    polyA[(short) (aOffset + 4 * i + 2)], polyA[(short) (aOffset + 4 * i + 3)],
                    polyB[(short) (bOffset + 4 * i + 2)], polyB[(short) (bOffset + 4 * i + 3)],
                    (short) (-1 * ZETAS[(short) (64 + i)]), result, (short) (roffset + 4 * i + 2)
            );
        }
    }

    /**
     * Converts all coefficients of a polynomial from normal domain to Montgomery domain with offset
     *
     * @param poly the polynomial array to convert
     * @param offset the starting offset in the polynomial array
     */
    public static void polyToMont(short[] poly, short offset) {
        for (short i = 0; i < paramsN; i++) {
            poly[(short) (offset + i)] = montgomeryReduce((poly[(short) (offset + i)] * 1353));
        }
    }

    /**
     * Applies Barrett reduction to all coefficients of a polynomial
     *
     * @param poly the polynomial array to reduce
     */
    public static void polyReduce(short[] poly) {
        polyReduce(poly, (short) 0);
    }

    /**
     * Applies Barrett reduction to all coefficients of a polynomial with offset
     *
     * @param poly the polynomial array to reduce
     * @param offset the starting offset in the polynomial array
     */
    public static void polyReduce(short[] poly, short offset) {
        for (short i = 0; i < paramsN; i++) {
            poly[(short) (offset + i)] = barrettReduce(poly[(short) (offset + i)]);
        }
    }

    /**
     * Conditionally subtracts the modulus Q from each coefficient with offset parameter
     *
     * @param poly the polynomial array
     * @param offset the starting offset in the polynomial array
     */
    public static void polyConditionalSubQ(short[] poly, short offset) {
        for (short i = offset; i < paramsN + offset; i++) {
            poly[i] = conditionalSubQ(poly[i]);
        }
    }

    /**
     * Adds two polynomials in-place (polyA = polyA + polyB)
     *
     * @param polyA the first polynomial array (operand and result)
     * @param polyB the second polynomial array
     */
    public static void polyAdd(short[] polyA, short[] polyB) {
        polyAdd(polyA, (short) 0, polyB, (short) 0);
    }

    /**
     * Adds two polynomials in-place with offset parameters
     *
     * @param polyA the first polynomial array (operand and result)
     * @param aOffset the starting offset in polyA
     * @param polyB the second polynomial array
     * @param bOffset the starting offset in polyB
     */
    public static void polyAdd(short[] polyA, short aOffset, short[] polyB, short bOffset) {
        for (short i = 0; i < paramsN; i++) {
            polyA[(short) (aOffset + i)] = (short) (polyA[(short) (aOffset + i)] + polyB[(short) (bOffset + i)]);
        }
    }

    /**
     * Subtracts two polynomials in-place (polyA = polyA - polyB)
     *
     * @param polyA the first polynomial array (operand and result)
     * @param polyB the second polynomial array
     */
    public static void polySub(short[] polyA, short[] polyB) {
        polySub(polyA, (short) 0, polyB, (short) 0);
    }

    /**
     * Subtracts two polynomials in-place with offset parameters
     *
     * @param polyA the first polynomial array (operand and result)
     * @param aOffset the starting offset in polyA
     * @param polyB the second polynomial array
     * @param bOffset the starting offset in polyB
     */
    public static void polySub(short[] polyA, short aOffset, short[] polyB, short bOffset) {
        for (short i = 0; i < paramsN; i++) {
            polyA[(short) (aOffset + i)] = (short) (polyA[(short) (aOffset + i)] - polyB[(short) (bOffset + i)]);
        }
    }


    /**
     * Compresses and serializes a single polynomial vector element
     *
     * @param polySingle the polynomial coefficients array
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param outC the output buffer for compressed bytes
     * @param outOffset the starting offset in the output buffer
     * @param temp temporary short array for intermediate calculations
     */
    public static void compressPolyVectorElement(short[] polySingle, int paramsK, byte[] outC, short outOffset, short[] temp) {
        polyConditionalSubQ(polySingle, (short) 0);

        if (paramsK == 2 || paramsK == 3) {
            for (short j = 0; j < 64; j++) { // 256 / 4 = 64
                for (short k = 0; k < 4; k++) {
                    int coeffBase = (polySingle[(short) (4 * j + k)] << 10) + 1665;

                    // Fix KyberSlash2
                    int a0 = coeffBase & 0x7FFF;
                    int a1 = coeffBase >>> 15;
                    int b0 = 12215;
                    int b1 = 39;
                    int m0 = a0 * b0;
                    int m1 = a1 * b0 + a0 * b1 + (m0 >>> 15);
                    int m2 = a1 * b1 + (m1 >>> 15);

                    temp[k] = (short) ((m2 >>> 2) & 0x3ff);
                }
                outC[(outOffset)] = (byte) (temp[0]);
                outC[(short) (outOffset + 1)] = (byte) ((temp[0] >> 8) | (temp[1] << 2));
                outC[(short) (outOffset + 2)] = (byte) ((temp[1] >> 6) | (temp[2] << 4)); // Atenção ao bufNoise[2] no seu código original, ajuste se necessário
                outC[(short) (outOffset + 3)] = (byte) ((temp[2] >> 4) | (temp[3] << 6));
                outC[(short) (outOffset + 4)] = (byte) (temp[3] >> 2);
                outOffset += 5;
            }
        } else {
            for (short j = 0; j < 32; j++) { // 256 / 8 = 32
                for (short k = 0; k < 8; k++) {
                    int coeffBase = (polySingle[(short) (8 * j + k)] << 11) + 1664;

                    // Fix KyberSlash2
                    int a0 = coeffBase & 0x7FFF;
                    int a1 = coeffBase >>> 15;
                    int b0 = 22492;
                    int b1 = 19;
                    int m0 = a0 * b0;
                    int m1 = a1 * b0 + a0 * b1 + (m0 >>> 15);
                    int m2 = a1 * b1 + (m1 >>> 15);

                    temp[k] = (short) ((m2 >>> 1) & 0x7ff);
                }
                outC[(outOffset)] = (byte) (temp[0]);
                outC[(short) (outOffset + 1)] = (byte) ((temp[0] >> 8) | (temp[1] << 3));
                outC[(short) (outOffset + 2)] = (byte) ((temp[1] >> 5) | (temp[2] << 6));
                outC[(short) (outOffset + 3)] = (byte) (temp[2] >> 2);
                outC[(short) (outOffset + 4)] = (byte) ((temp[2] >> 10) | (temp[3] << 1));
                outC[(short) (outOffset + 5)] = (byte) ((temp[3] >> 7) | (temp[4] << 4));
                outC[(short) (outOffset + 6)] = (byte) ((temp[4] >> 4) | (temp[5] << 7));
                outC[(short) (outOffset + 7)] = (byte) (temp[5] >> 1);
                outC[(short) (outOffset + 8)] = (byte) ((temp[5] >> 9) | (temp[6] << 2));
                outC[(short) (outOffset + 9)] = (byte) ((temp[6] >> 6) | (temp[7] << 5));
                outC[(short) (outOffset + 10)] = (byte) (temp[7] >> 3);
                outOffset += 11;
            }
        }
    }

    /**
     * De-serializes and decompresses a single polynomial vector element
     * <p>
     * Decompression is lossy, so results will not exactly match the original
     *
     * @param inC the compressed byte array
     * @param inOffset the starting offset in the byte array
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param outPoly the output polynomial array
     * @param outOffset the starting offset in the output polynomial array
     */
    public static void decompressPolyVectorElement(byte[] inC, short inOffset, int paramsK, short[] outPoly, short outOffset) {
        if (paramsK == 2 || paramsK == 3) {
            for (short j = 0; j < 64; j++) { // 256 / 4 = 64 iterações

                int t0 = ((inC[inOffset] & 0xFF)) | ((inC[(short) (inOffset + 1)] & 0xFF) << 8);
                int t1 = ((inC[(short) (inOffset + 1)] & 0xFF) >> 2) | ((inC[(short) (inOffset + 2)] & 0xFF) << 6);
                int t2 = ((inC[(short) (inOffset + 2)] & 0xFF) >> 4) | ((inC[(short) (inOffset + 3)] & 0xFF) << 4);
                int t3 = ((inC[(short) (inOffset + 3)] & 0xFF) >> 6) | ((inC[(short) (inOffset + 4)] & 0xFF) << 2);

                inOffset += 5;

                outPoly[(outOffset)] = (short) (((t0 & 0x3FF) * paramsQ + 512) >> 10);
                outPoly[(short) (outOffset + 1)] = (short) (((t1 & 0x3FF) * paramsQ + 512) >> 10);
                outPoly[(short) (outOffset + 2)] = (short) (((t2 & 0x3FF) * paramsQ + 512) >> 10);
                outPoly[(short) (outOffset + 3)] = (short) (((t3 & 0x3FF) * paramsQ + 512) >> 10);

                outOffset = (short) (outOffset + 4);
            }
        } else { // ML-KEM-1024 (paramsK == 4)
            for (short j = 0; j < 32; j++) { // 256 / 8 = 32 iterações

                int t0 = ((inC[inOffset] & 0xFF)) | ((inC[(short) (inOffset + 1)] & 0xFF) << 8);
                int t1 = ((inC[(short) (inOffset + 1)] & 0xFF) >> 3) | ((inC[(short) (inOffset + 2)] & 0xFF) << 5);
                int t2 = ((inC[(short) (inOffset + 2)] & 0xFF) >> 6) | ((inC[(short) (inOffset + 3)] & 0xFF) << 2) | ((inC[(short) (inOffset + 4)] & 0xFF) << 10);
                int t3 = ((inC[(short) (inOffset + 4)] & 0xFF) >> 1) | ((inC[(short) (inOffset + 5)] & 0xFF) << 7);
                int t4 = ((inC[(short) (inOffset + 5)] & 0xFF) >> 4) | ((inC[(short) (inOffset + 6)] & 0xFF) << 4);
                int t5 = ((inC[(short) (inOffset + 6)] & 0xFF) >> 7) | ((inC[(short) (inOffset + 7)] & 0xFF) << 1) | ((inC[(short) (inOffset + 8)] & 0xFF) << 9);
                int t6 = ((inC[(short) (inOffset + 8)] & 0xFF) >> 2) | ((inC[(short) (inOffset + 9)] & 0xFF) << 6);
                int t7 = ((inC[(short) (inOffset + 9)] & 0xFF) >> 5) | ((inC[(short) (inOffset + 10)] & 0xFF) << 3);

                inOffset += 11; // Avança 11 bytes no Ciphertext

                outPoly[(short) (outOffset + 0)] = (short) (((t0 & 0x7FF) * paramsQ + 1024) >> 11);
                outPoly[(short) (outOffset + 1)] = (short) (((t1 & 0x7FF) * paramsQ + 1024) >> 11);
                outPoly[(short) (outOffset + 2)] = (short) (((t2 & 0x7FF) * paramsQ + 1024) >> 11);
                outPoly[(short) (outOffset + 3)] = (short) (((t3 & 0x7FF) * paramsQ + 1024) >> 11);
                outPoly[(short) (outOffset + 4)] = (short) (((t4 & 0x7FF) * paramsQ + 1024) >> 11);
                outPoly[(short) (outOffset + 5)] = (short) (((t5 & 0x7FF) * paramsQ + 1024) >> 11);
                outPoly[(short) (outOffset + 6)] = (short) (((t6 & 0x7FF) * paramsQ + 1024) >> 11);
                outPoly[(short) (outOffset + 7)] = (short) (((t7 & 0x7FF) * paramsQ + 1024) >> 11);

                outOffset = (short) (outOffset + 8); // Avança 8 posições no polinômio
            }
        }
    }

    /*
    -----------------------------------------------------------------------------------------

                                     Byte Operations

    -----------------------------------------------------------------------------------------
     */

    /**
     * Converts 4 bytes from an array into a 32-bit unsigned integer
     *
     * @param x the byte array
     * @param off the starting offset in the array
     * @return the 32-bit unsigned integer value
     */
    public static int convertByteTo32BitUnsignedInt(byte[] x, int off) {
        int r = (x[(short) off] & 0xFF);
        r = r | ((x[(short) ++off] & 0xFF) << 8);
        r = r | ((x[(short) ++off] & 0xFF) << 16);
        r = r | (x[(short) ++off] << 24);
        return r;
    }

    /**
     * Converts 3 bytes from an array into a 24-bit unsigned integer
     *
     * @param x the byte array
     * @param off the starting offset in the array
     * @return the 24-bit unsigned integer value
     */
    public static int convertByteTo24BitUnsignedInt(byte[] x, int off) {
        int r = (x[(short) off] & 0xFF);
        r = r | ((x[(short) ++off] & 0xFF) << 8);
        r = r | ((x[(short) ++off] & 0xFF) << 16);
        return r;
    }

    /**
     * Generates a polynomial with coefficients from a centered binomial distribution
     * based on uniformly random bytes
     *
     * @param buf the input buffer of uniformly random bytes
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param result the output polynomial array
     * @param roffset the starting offset in the output array
     */
    public static void generateCBDPoly(byte[] buf, int paramsK, short[] result, short roffset) {
        int t, d; // both unsigned
        int a, b;
        if (paramsK == 2) {
            for (short i = 0; i < paramsN / 4; i++) {
                t = convertByteTo24BitUnsignedInt(buf, 3 * i);
                d = t & 0x00249249;
                d = d + ((t >> 1) & 0x00249249);
                d = d + ((t >> 2) & 0x00249249);
                for (short j = 0; j < 4; j++) {
                    a = (d >> (6 * j)) & 0x7;
                    b = (d >> (6 * j + paramsETAK512)) & 0x7;
                    result[(short) (roffset + 4 * i + j)] = (short) (a - b);
                }
            }
        } else {
            for (short i = 0; i < paramsN / 8; i++) {
                t = convertByteTo32BitUnsignedInt(buf, 4 * i);
                d = t & 0x55555555;
                d = d + ((t >> 1) & 0x55555555);
                for (short j = 0; j < 8; j++) {
                    a = (d >> (4 * j)) & 0x3;
                    b = (d >> (4 * j + paramsETAK768K1024)) & 0x3;
                    result[(short) (roffset + 8 * i + j)] = (short) (a - b);
                }
            }
        }
    }

    /**
     * Performs a constant-time subtraction with modulus Q from a coefficient if it is greater than Q
     *
     * @param a the coefficient value
     * @return the reduced coefficient value
     */
    public static short conditionalSubQ(short a) {
        a = (short) (a - paramsQ);
        a = (short) (a + ((int) ((int) a >> 15) & paramsQ));
        return a;
    }

    /*
    -----------------------------------------------------------------------------------------

                     Indistinguishability under Chosen-Plaintext Attack (IND-CPA)

    -----------------------------------------------------------------------------------------
     */

    /**
     * Runs rejection sampling on uniform random bytes to generate uniform random integers modulo Q
     *
     * @param uniformR the output array for uniform random integers
     * @param roffset the starting offset in the output array
     * @param buf the input buffer of random bytes
     * @param bufOffset the starting offset in the input buffer
     * @param bufl the length of the input buffer
     * @param l the number of uniform random values to generate
     * @return the number of uniform random values generated
     */
    public static short generateUniform(short[] uniformR, short roffset, byte[] buf, short bufOffset, int bufl, int l) {
        int d1;
        int d2;
        short uniformI = 0; // Always start at 0
        int j = 0;
        while ((uniformI < l) && ((j + 3) <= bufl)) {
            d1 = (int) (((((int) (buf[(short) (bufOffset + j)] & 0xFF))) | (((int) (buf[(short) (bufOffset + j + 1)] & 0xFF)) << 8)) & 0xFFF);
            d2 = (int) (((((int) (buf[(short) (bufOffset + j + 1)] & 0xFF)) >> 4) | (((int) (buf[(short) (bufOffset + j + 2)] & 0xFF)) << 4)) & 0xFFF);
            j = j + 3;
            if (d1 < paramsQ) {
                uniformR[(short) (uniformI + roffset)] = (short) d1;
                uniformI++;
            }
            if (uniformI < l && d2 < paramsQ) {
                uniformR[(short) (uniformI + roffset)] = (short) d2;
                uniformI++;
            }
        }
        return uniformI;
    }

    /**
     * Generates a polynomial vector matrix from the given seed
     *
     * @param seed the seed byte array (32 bytes)
     * @param transposed whether to generate the transposed matrix
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param i the row index
     * @param j the column index
     * @param r the output matrix array
     */
    public static void generateMatrix(byte[] seed, boolean transposed, int paramsK, short i, short j, short[] r) {
        generateMatrix(seed, (short) 0, transposed, paramsK, i, j, r);
    }

    /**
     * Generates a polynomial vector matrix from the given seed with offset parameter
     *
     * @param seed the seed byte array (32 bytes)
     * @param seedOffset the starting offset in the seed array
     * @param transposed whether to generate the transposed matrix
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param i the row index
     * @param j the column index
     * @param r the output matrix array
     */
    public static void generateMatrix(byte[] seed, short seedOffset, boolean transposed, int paramsK, short i, short j, short[] r) {
        reset();
        absorb(seed, seedOffset, (short) 32, paramsSHAKE128_Rate, SHAKEpadding);
        if (transposed) {
            hashBuffer[0] = (byte) i;
            hashBuffer[1] = (byte) j;
        } else {
            hashBuffer[0] = (byte) j;
            hashBuffer[1] = (byte) i;
        }
        absorb(hashBuffer, (short) 0, (short) 2, paramsSHAKE128_Rate, SHAKEpadding);
        squeeze(hashBuffer, (short) 0, (short) 504, paramsSHAKE128_Rate, SHAKEpadding);
        int ui = generateUniform(r, (short) 0, hashBuffer, (short) 0, 504, paramsN);
        while (ui < paramsN) {
            squeeze(hashBuffer, (short) 504, (short) 168, paramsSHAKE128_Rate, SHAKEpadding);

            short ctrn = generateUniform(r, (short) ui, hashBuffer, (short) 504, (short) 168, (short) (paramsN - ui));

            ui = (short) (ui + ctrn);
        }
    }

    /**
     * Pseudo-random function that derives a deterministic array of random bytes
     * from a key and nonce using SHAKE256
     *
     * @param l the number of bytes to generate
     * @param seed the secret key byte array
     * @param seedOffset the starting offset in the key array
     * @param nonce the nonce byte value
     * @param bufHash the output buffer for derived bytes
     */
    public static void generatePRFByteArray(int l, byte[] seed, short seedOffset, byte nonce, byte[] bufHash) {
        reset();
        absorb(seed, seedOffset, (short) 32, paramsSHAKE256_Rate, SHAKEpadding);
        bufHash[0] = nonce;
        absorb(bufHash, (short) 0, (short) 1, paramsSHAKE256_Rate, SHAKEpadding);
        squeeze(bufHash, (short) 0, (short) l, paramsSHAKE256_Rate,  SHAKEpadding);
    }

    /**
     * Generates public and private keys for the CPA-secure encryption scheme underlying ML-KEM
     *
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param originalSeed the original seed bytes for key generation
     */
    protected static void generateMLKEMKeys(int paramsK, byte[] originalSeed) {
        try {
            reset();
            absorb(originalSeed, (short) 0, (short) paramsSymBytes, paramsSHA3_512_Rate,  SHA3padding);
            originalSeed[0] = (byte) paramsK;
            absorb(originalSeed, (short) 0, (short) 1, paramsSHA3_512_Rate,  SHA3padding);
            squeeze(seedBuf, (short) 0, (short) 64, paramsSHA3_512_Rate,  SHA3padding);

            // Generate Decapsulation Key
            byte nonce = (byte) 0;
            for (short i = 0; i < paramsK; i++) {
                getNoisePoly(seedBuf, (short) 32, nonce, paramsK, bufNoise, (short) 0);
                nonce++;
                polyNTT(bufNoise, (short) 0);
                polyReduce(bufNoise, (short) 0);
                polyToBytes(bufNoise, (short) 0, packedDK, (short) (i * paramsPolyBytes));
            }

            // Generate Encapsulation Key
            byte nonceE = (byte) paramsK;
            for (short i = 0; i < paramsK; i++) {
                for (short k = 0; k < 256; k++) {
                    bufPolyTemp[k] = 0;
                }

                for (short j = 0; j < paramsK; j++) {
                    generateMatrix(seedBuf, false, paramsK, i, j, bufMatrix);

                    polyFromBytes(packedDK, (short) (j * paramsPolyBytes), bufNoise, (short) 0);

                    polyBaseMulMont(bufMatrix, 0, bufNoise, (short) 0, bufMatrix, (short) 0);

                    polyAdd(bufPolyTemp, (short) 0, bufMatrix, (short) 0);
                }
                polyToMont(bufPolyTemp, (short) 0);

                getNoisePoly(seedBuf, (short) 32, nonceE, paramsK, bufNoise, (short) 0);
                nonceE++;
                polyNTT(bufNoise, (short) 0);
                polyAdd(bufPolyTemp, (short) 0, bufNoise, (short) 0);
                polyReduce(bufPolyTemp, (short) 0);
                polyToBytes(bufPolyTemp, (short) 0, packedDK, (short) ((paramsPolyBytes) * (paramsK + i)));
            }

            Util.arrayCopyNonAtomic(seedBuf, (short) 0, packedDK, (short) (2 * paramsK * paramsPolyBytes), (short) 32);


            for (short i = 0; i < paramsN; i++) {
                bufPolyTemp[i] = 0;
                bufMatrix[i] = 0;
                bufNoise[i] = 0;
            }

        } catch (Exception ex) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * Generates an ML-KEM-512 key pair (K=2) from a seed
     *
     * @param seed the seed bytes for key generation
     */
    public static void generateKeys512Internal(byte[] seed) {
        int paramsK = 2;
        try {
            //copy first z into the secret key as the buffer will be reused
            int offsetEnd = packedDK.length - 32;
            Util.arrayCopyNonAtomic(seed, (short) 32, packedDK, (short) offsetEnd, (short) 32);

            generateMLKEMKeys(paramsK, seed);

            offsetEnd -= 32;
            absorb(packedDK, (short) (paramsK * paramsPolyBytes), (short) MLKEM512PKBytes, paramsSHA3_256_Rate,  SHA3padding);
            squeeze(packedDK, (short) offsetEnd, (short) 32, paramsSHA3_256_Rate,  SHA3padding);
        } catch (Exception ex) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * Generates an ML-KEM-768 key pair (K=3) from a seed
     *
     * @param seed the seed bytes for key generation
     */
    public static void generateKeys768Internal(byte[] seed) {
        int paramsK = 3;
        try {
            //copy first z into the secret key as the buffer will be reused
            int offsetEnd = packedDK.length - 32;
            Util.arrayCopyNonAtomic(seed, (short) 32, packedDK, (short) offsetEnd, (short) 32);

            generateMLKEMKeys(paramsK, seed);

            offsetEnd -= 32;
            reset();
            absorb(packedDK, (short) (paramsK * paramsPolyBytes), (short) MLKEM768PKBytes, paramsSHAKE256_Rate, SHAKEpadding);
            squeeze(packedDK, (short) offsetEnd, (short) 32, paramsSHAKE256_Rate,  SHA3padding);
        } catch (Exception ex) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * Instance method wrapper to generate an ML-KEM-768 key pair with random seed
     */
    private void generateKeys768() {
        try {
            sr.generateData(seedBuf, (short) 0, (short) paramsSymBytes);

            sr.generateData(seedBuf, (short) 32, (short) paramsSymBytes);

            generateKeys768Internal(seedBuf);
        } catch (Exception ex) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * Instance method wrapper to generate an ML-KEM-512 key pair with random seed
     */
    private void generateKeys512() {
        try {
            sr.generateData(seedBuf, (short) 0, (short) paramsSymBytes);

            sr.generateData(seedBuf, (short) 32, (short) paramsSymBytes);

            generateKeys512Internal(seedBuf);
        } catch (Exception ex) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * Generates an ML-KEM-1024 key pair (K=4) from a seed
     *
     * @param seed the seed bytes for key generation
     */
    public static void generateKeys1024Internal(byte[] seed) {
        int paramsK = 4;
        try {
            //copy first z into the secret key as the buffer will be reused
            int offsetEnd = packedDK.length - 32;
            Util.arrayCopyNonAtomic(seed, (short) 32, packedDK, (short) offsetEnd, (short) 32);

            generateMLKEMKeys(paramsK, seed);

            offsetEnd -= 32;
            reset();
            absorb(packedDK, (short) (paramsK * paramsPolyBytes), (short) MLKEM1024PKBytes, paramsSHA3_256_Rate,  SHA3padding);
            squeeze(packedDK, (short) offsetEnd, (short) 32, paramsSHA3_256_Rate,  SHA3padding);
        } catch (Exception ex) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * Instance method wrapper to generate an ML-KEM-1024 key pair with random seed
     */
    private void generateKeys1024() {
        try {
            sr.generateData(seedBuf, (short) 0, (short) paramsSymBytes);

            sr.generateData(seedBuf, (short) 32, (short) paramsSymBytes);

            generateKeys1024Internal(seedBuf);
        } catch (Exception ex) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * CPA encryption: encrypts a message using the public key to produce ciphertext
     *
     * @param m the message bytes (32 bytes)
     * @param coins the randomness/coins for encryption
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     * @param C the output ciphertext buffer
     */
    public static void encrypt(byte[] m, byte[] coins, int paramsK, byte[] C) {

        for (short i = 0; i < paramsK; i++) {
            for (short l = 0; l < 256; l++) {
                bufPolyTemp[l] = 0;
            }
            for (short j = 0; j < paramsK; j++) {
                getNoisePoly(coins, (short) 32, (byte) (j), paramsK, bufNoise, (short) 0);
                polyNTT(bufNoise, (short) 0);

                generateMatrix(packedDK, (short) (2 * paramsK * paramsPolyBytes), true, paramsK, i, j, bufMatrix);

                polyBaseMulMont(bufMatrix, 0, bufNoise, (short) 0, bufMatrix, (short) 0);

                polyAdd(bufPolyTemp, bufMatrix);
            }
            polyInverseNttToMont(bufPolyTemp, (short) 0);

            getNoisePoly(coins, (short) 32, (byte) (i + paramsK), 3, bufNoise, (short) 0);

            polyAdd(bufPolyTemp, bufNoise);

            polyReduce(bufPolyTemp, (short) 0);

            short compressSize = (short) ((paramsK == 4) ? 352 : 320);

            short offsetC1 = (short) (i * compressSize);

            compressPolyVectorElement(bufPolyTemp, paramsK, C, offsetC1, bufNoise);
        }

        for (short l = 0; l < 256; l++) {
            bufPolyTemp[l] = 0;
        }

        for (short j = 0; j < paramsK; j++) {
            getNoisePoly(coins, (short) 32, (byte) (j), paramsK, bufNoise, (short) 0);
            polyNTT(bufNoise, (short) 0);

            polyFromBytes(packedDK, ((paramsK + j) * paramsPolyBytes), bufMatrix, (short) 0);

            polyBaseMulMont(bufMatrix, (short) 0, bufNoise, (short) 0, bufMatrix, (short) 0);

            polyAdd(bufPolyTemp, bufMatrix);
        }

        polyInverseNttToMont(bufPolyTemp, (short) 0);

        getNoisePoly(coins, (short) 32, (byte) (paramsK * 2), 3, bufNoise, (short) 0);

        polyFromData(m, bufMatrix, (short) 0);

        polyAdd(bufMatrix, bufNoise);

        polyAdd(bufPolyTemp, bufMatrix);

        polyReduce(bufPolyTemp);

        short offsetC2 = (short) ((paramsK == 2) ? 640 : (paramsK == 3) ? 960 : 1408);

        compressPoly(bufPolyTemp, (short) 0, paramsK, C, offsetC2, hashBuffer);

        for (short i = 0; i < paramsN; i++) {
            bufPolyTemp[i] = 0;
            bufMatrix[i] = 0;
            bufNoise[i] = 0;
        }
    }

    /**
     * ML-KEM-512 encapsulation: derives shared secret and ciphertext from a message
     *
     * @param m the message bytes (32 bytes)
     */
    public static void encaps512Internal(byte[] m) {
        short paramsK = 2;
        reset();
        absorb(m, (short) 0, (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        absorb(packedDK, (short) (packedDK.length - 64), (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        squeeze(seedBuf, (short) 0, (short) 64, paramsSHA3_512_Rate,  SHA3padding);

        Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);

        encrypt(m, seedBuf, paramsK, bufC);

    }

    /**
     * ML-KEM-512 encapsulation with random message generation
     */
    private static void encapsulation512() {
        sr.generateData(message, (short) 0, (short) paramsSymBytes);

        encaps512Internal(message);

        for (short i = 0; i < 32; i++) {
            message[i] = 0;
        }
    }

    /**
     * ML-KEM-768 encapsulation: derives shared secret and ciphertext from a message
     *
     * @param m the message bytes (32 bytes)
     */
    private static void encaps768Internal(byte[] m) {
        short paramsK = 3;
        reset();
        absorb(m, (short) 0, (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        absorb(packedDK, (short) (packedDK.length - 64), (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        squeeze(seedBuf, (short) 0, (short) 64, paramsSHA3_512_Rate,  SHA3padding);

        encrypt(m, seedBuf, paramsK, bufC);

        Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);
    }

    /**
     * ML-KEM-768 encapsulation with random message generation
     */
    private static void encapsulation768() {
        sr.generateData(message, (short) 0, (short) paramsSymBytes);

        encaps768Internal(message);

        for (short i = 0; i < 32; i++) {
            message[i] = 0;
        }
    }

    /**
     * ML-KEM-1024 encapsulation: derives shared secret and ciphertext from a message
     *
     * @param m the message bytes (32 bytes)
     */
    private static void encaps1024Internal(byte[] m) {
        short paramsK = 4;
        reset();
        absorb(m, (short) 0, (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        absorb(packedDK, (short) (packedDK.length - 64), (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        squeeze(seedBuf, (short) 0, (short) 64, paramsSHA3_512_Rate,  SHA3padding);

        encrypt(m, seedBuf, paramsK, bufC);

        Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);
    }

    /**
     * ML-KEM-1024 encapsulation with random message generation
     */
    private static void encapsulation1024() {
        sr.generateData(message, (short) 0, (short) paramsSymBytes);

        encaps1024Internal(message);

        for (short i = 0; i < 32; i++) {
            message[i] = 0;
        }
    }

    /**
     * CPA decryption: decrypts a ciphertext using the private key to recover the message
     *
     * @param message the output buffer for decrypted message
     * @param paramsK the security parameter (2 for ML-KEM-512, 3 for ML-KEM-768, 4 for ML-KEM-1024)
     */
    public static void decrypt(byte[] message, int paramsK) {
        for (short i = 0; i < paramsN; i++) {
            bufPolyTemp[i] = 0;
        }

        for (short i = 0; i < paramsK; i++) {
            polyFromBytes(packedDK, (short) (i * paramsPolyBytes), bufMatrix, (short) 0);

            short Coffset = (short) ((paramsK == 4) ? 352 : 320);
            decompressPolyVectorElement(bufC, (short) (i * Coffset), paramsK, bufNoise, (short) 0);
            polyNTT(bufNoise, (short) 0);

            polyBaseMulMont(bufMatrix, (short) 0, bufNoise, (short) 0, bufMatrix, (short) 0);

            polyAdd(bufPolyTemp, bufMatrix);
        }

        polyInverseNttToMont(bufPolyTemp, (short) 0);

        short offsetC2 = (short) ((paramsK == 2) ? 640 : (paramsK == 3) ? 960 : 1408);

        decompressPoly(bufC, offsetC2, paramsK, bufNoise, (short) 0, hashBuffer);

        polySub(bufNoise, bufPolyTemp);

        polyReduce(bufNoise);

        polyToMsg(bufNoise, (short) 0, message, (short) 0);

        for (short i = 0; i < paramsN; i++) {
            bufPolyTemp[i] = 0;
            bufMatrix[i] = 0;
            bufNoise[i] = 0;
        }
    }

    /**
     * ML-KEM-512 decapsulation: extracts shared secret from ciphertext using private key
     *
     * @param message the decrypted message bytes
     */
    public static void decaps512Internal(byte[] message) {
        short paramsK = 2;
        decrypt(message, paramsK);
        reset();
        absorb(message, (short) 0, (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        absorb(packedDK, (short) (packedDK.length - 64), (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        squeeze(seedBuf, (short) 0, (short) 64, paramsSHA3_512_Rate,  SHA3padding);

        Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);

        encrypt(message, seedBuf, paramsK, bufCRed);

        reset();
        absorb(packedDK, (short) (packedDK.length - 32), (short) 32, paramsSHAKE256_Rate, SHAKEpadding);
        absorb(bufC, (short) 0, (short) bufC.length, paramsSHAKE256_Rate, SHAKEpadding);
        squeeze(seedBuf, (short) 0, (short) 32, paramsSHAKE256_Rate,  SHAKEpadding);

        if (Util.arrayCompare(bufCRed, (short) 0, bufC, (short) 0, (short) bufC.length) != 0) {
            // If ciphertexts don't match, overwrite shared secret with hash of z
            Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);
        }
    }

    /**
     * ML-KEM-512 decapsulation wrapper
     */
    private static void decapsulation512() {
        decaps512Internal(message);
    }

    /**
     * ML-KEM-768 decapsulation: extracts shared secret from ciphertext using private key
     *
     * @param message the decrypted message bytes
     */
    public static void decaps768Internal(byte[] message) {
        short paramsK = 3;
        decrypt(message, paramsK);
        reset();
        absorb(message, (short) 0, (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        absorb(packedDK, (short) (packedDK.length - 64), (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        squeeze(seedBuf, (short) 0, (short) 64, paramsSHA3_512_Rate,  SHA3padding);

        Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);

        encrypt(message, seedBuf, paramsK, bufCRed);

        reset();
        absorb(packedDK, (short) (packedDK.length - 32), (short) 32, paramsSHAKE256_Rate, SHAKEpadding);
        absorb(bufC, (short) 0, (short) bufC.length, paramsSHAKE256_Rate, SHAKEpadding);
        squeeze(seedBuf, (short) 0, (short) 32, paramsSHAKE256_Rate,  SHAKEpadding);

        if (Util.arrayCompare(bufCRed, (short) 0, bufC, (short) 0, (short) bufC.length) != 0) {
            // If ciphertexts don't match, overwrite shared secret with hash of z
            Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);
        }
    }

    /**
     * ML-KEM-768 decapsulation wrapper
     */
    private static void decapsulation768() {
        decaps768Internal(message);
    }

    /**
     * ML-KEM-1024 decapsulation: extracts shared secret from ciphertext using private key
     *
     * @param message the decrypted message bytes
     */
    public static void decaps1024Internal(byte[] message) {
        short paramsK = 4;
        decrypt(message, paramsK);
        reset();
        absorb(message, (short) 0, (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        absorb(packedDK, (short) (packedDK.length - 64), (short) 32, paramsSHA3_512_Rate,  SHA3padding);
        squeeze(seedBuf, (short) 0, (short) 64, paramsSHA3_512_Rate,  SHA3padding);

        Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);

        encrypt(message, seedBuf, paramsK, bufCRed);

        reset();
        absorb(packedDK, (short) (packedDK.length - 32), (short) 32, paramsSHAKE256_Rate, SHAKEpadding);
        absorb(bufC, (short) 0, (short) bufC.length, paramsSHAKE256_Rate, SHAKEpadding);
        squeeze(seedBuf, (short) 0, (short) 32, paramsSHAKE256_Rate,  SHAKEpadding);

        if (Util.arrayCompare(bufCRed, (short) 0, bufC, (short) 0, (short) bufC.length) != 0) {
            // If ciphertexts don't match, overwrite shared secret with hash of z
            Util.arrayCopyNonAtomic(seedBuf, (short) 0, secretKey, (short) 0,  MLKEMSSBytes);
        }
    }

    /**
     * ML-KEM-1024 decapsulation wrapper
     */
    private static void decapsulation1024() {
        decaps1024Internal(message);
    }
}