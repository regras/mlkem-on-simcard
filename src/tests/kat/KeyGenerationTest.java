package com.swiftcryptollc.crypto.provider;

// ...existing code...
import com.swiftcryptollc.crypto.applet.MLKEMApplet;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.*;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

public class KeyGenerationTest {

    static class KeyGenTestVector {
        int count;
        byte[] d;
        byte[] z;
        byte[] publicKey;
        byte[] secretKey;
    }

    @Test
    public void testAllKeyGenerationVectors_AllLevels() {
        String[] parameterSets = new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
        int totalTested = 0;

        for (String paramSet : parameterSets) {
            List<KeyGenTestVector> vectors = loadTestVectorsFromJSON("internalProjectionKeyGen.json", paramSet);

            assertFalse(vectors.isEmpty(), "No test vectors loaded for " + paramSet + " from internalProjectionKeyGen.json");

            int successCount = 0;
            for (KeyGenTestVector tv : vectors) {
                try {
                    testKeyGenerationForParameter(tv, paramSet);
                    successCount++;
                } catch (Exception e) {
                    fail("Test vector " + tv.count + " failed for " + paramSet + ": " + e.getMessage());
                }
            }

            System.out.println("KeyGenerationTest: Successfully tested " + successCount + " test vectors for " + paramSet);
            totalTested += successCount;
        }

        System.out.println("KeyGenerationTest: Total tested vectors across levels: " + totalTested);
    }

    private void testKeyGenerationForParameter(KeyGenTestVector tv, String parameterSet) throws Exception {
        // Combine d and z into a 64-byte seed (d is first 32 bytes, z is second 32 bytes)
        byte[] seed = new byte[64];
        System.arraycopy(tv.d, 0, seed, 0, 32);
        System.arraycopy(tv.z, 0, seed, 32, 32);

        // Map parameterSet to paramsK and the internal constructor level used by MLKEMApplet
        int paramsK;
        short ctorLevel;
        switch (parameterSet) {
            case "ML-KEM-512":
                paramsK = 2; // Kyber512
                ctorLevel = 1; // constructor treats 1 or 2 as 512
                break;
            case "ML-KEM-768":
                paramsK = 3; // Kyber768
                ctorLevel = 3;
                break;
            case "ML-KEM-1024":
                paramsK = 4; // Kyber1024
                ctorLevel = 5;
                break;
            default:
                throw new IllegalArgumentException("Unknown parameter set: " + parameterSet);
        }

        // Ensure MLKEMApplet static state is initialized for this security level by invoking its private constructor
        Constructor<MLKEMApplet> ctor = MLKEMApplet.class.getDeclaredConstructor(short.class);
        ctor.setAccessible(true);
        // instantiate to initialize static buffers (constructor sets packedDK based on level)
        ctor.newInstance(ctorLevel);

        // Call the appropriate generator
        switch (parameterSet) {
            case "ML-KEM-512":
                MLKEMApplet.generateKeys512Internal(seed);
                break;
            case "ML-KEM-768":
                MLKEMApplet.generateKeys768Internal(seed);
                break;
            case "ML-KEM-1024":
                MLKEMApplet.generateKeys1024Internal(seed);
                break;
        }

        // Access the static packedDK field to extract the keys
        byte[] packedDK = MLKEMApplet.packedDK;

        // Extract the full private key (dk) using expected length from test vector
        byte[] generatedDK = Arrays.copyOfRange(packedDK, 0, tv.secretKey.length);

        // Compute public key offset and extract expected length
        int pkOffset = paramsK * MLKEMApplet.paramsPolyBytes;
        if (pkOffset + tv.publicKey.length > packedDK.length) {
            throw new AssertionError("Packed DK too small for expected public key extraction for " + parameterSet);
        }
        byte[] generatedEK = Arrays.copyOfRange(packedDK, pkOffset, pkOffset + tv.publicKey.length);

        assertArrayEquals(tv.secretKey, generatedDK,
                "Private Key mismatch for vector " + tv.count + " (" + parameterSet + ")");
        assertArrayEquals(tv.publicKey, generatedEK,
                "Public Key mismatch for vector " + tv.count + " (" + parameterSet + ")");
    }

    private List<KeyGenTestVector> loadTestVectorsFromJSON(String filename, String parameterSet) {
        List<KeyGenTestVector> vectors = new ArrayList<>();

        try {
            InputStream inputStream = Thread.currentThread().getContextClassLoader()
                    .getResourceAsStream("assets/" + filename);

            if (inputStream == null) {
                fail("Test vector file not found: " + filename);
                return vectors;
            }

            JSONTokener tokener = new JSONTokener(new InputStreamReader(inputStream));
            JSONObject root = new JSONObject(tokener);
            JSONArray testGroups = root.getJSONArray("testGroups");

            for (int i = 0; i < testGroups.length(); i++) {
                JSONObject testGroup = testGroups.getJSONObject(i);
                String param = testGroup.getString("parameterSet");

                if (param.equals(parameterSet)) {
                    JSONArray tests = testGroup.getJSONArray("tests");

                    for (int j = 0; j < tests.length(); j++) {
                        JSONObject test = tests.getJSONObject(j);
                        KeyGenTestVector tv = new KeyGenTestVector();
                        tv.count = test.getInt("tcId");
                        tv.d = hexToBytes(test.getString("d"));
                        tv.z = hexToBytes(test.getString("z"));
                        tv.publicKey = hexToBytes(test.getString("ek"));
                        tv.secretKey = hexToBytes(test.getString("dk"));
                        vectors.add(tv);
                    }
                    break;
                }
            }

            inputStream.close();
            System.out.println("Loaded " + vectors.size() + " test vectors from " + filename + " for " + parameterSet);

        } catch (Exception e) {
            fail("Exception reading test vectors: " + e.getMessage());
        }

        return vectors;
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }
}
