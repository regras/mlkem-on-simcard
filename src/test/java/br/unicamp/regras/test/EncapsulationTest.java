package br.unicamp.regras.test;

import br.unicamp.regras.applet.MLKEMApplet;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

public class EncapsulationTest {

    static class EncapsTestVector {
        int tcId;
        String parameterSet;
        byte[] dk;
        byte[] m;
        byte[] k;
        byte[] c;
    }

    /**
     * Executes the encapsulation test for ML-KEM-512 parameter set.
     */
    @Test
    public void testEncapsulation512() {
        runEncapsulationSuite("ML-KEM-512", (short) 1);
    }

    /**
     * Executes the encapsulation test for ML-KEM-768 parameter set.
     */
    @Test
    public void testEncapsulation768() {
        runEncapsulationSuite("ML-KEM-768", (short) 3);
    }

    /**
     * Executes the encapsulation test for ML-KEM-1024 parameter set.
     */
    @Test
    public void testEncapsulation1024() {
        runEncapsulationSuite("ML-KEM-1024", (short) 5);
    }

    /**
     * This test method executes the encapsulation algorithm in the specific level
     * @param parameterSet The parameter set to test (e.g., "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024").
     * @param level The security level to test.
     */
    private void runEncapsulationSuite(String parameterSet, short level) {
        List<EncapsTestVector> vectors = loadTestVectorsFromJSON("internalProjectionEncaps.json", parameterSet, "encapsulation");

        assertFalse(vectors.isEmpty(), "No test vectors loaded for " + parameterSet + " from internalProjectionEncaps.json");

        int successCount = 0;
        for (EncapsTestVector tv : vectors) {
            try {
                runEncapsulationVector(tv, level);
                successCount++;
            } catch (AssertionError e) {
                fail("Test vector " + tv.tcId + " failed for " + parameterSet + ": " + e.getMessage());
            }
        }

        System.out.println("EncapsulationTest: Successfully tested " + successCount + " test vectors for " + parameterSet);
    }

    /**
     * This method tests key generation for a specific parameter set using the provided test vector.
     * It initializes the MLKEMApplet with the given level, sets the packedDK from the test vector, and performs encapsulation.
     * It then asserts that the generated shared secret and ciphertext match the expected values from the test vector.
     *
     @param tv The test vector containing d, z, expected public key, and expected secret key.
     @param level The parameter set to test (e.g., "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024").
     */
    private void runEncapsulationVector(EncapsTestVector tv, short level) {
        new MLKEMApplet(level);

        MLKEMApplet.packedDK = tv.dk.clone();

        byte[] message = tv.m.clone();
        switch (level) {
            case 1:
            case 2:
                MLKEMApplet.encaps512Internal(message);
                break;
            case 3:
                MLKEMApplet.encaps768Internal(message);
                break;
            case 5:
                MLKEMApplet.encaps1024Internal(message);
                break;
            default:
                fail("Unsupported ML-KEM level: " + level);
        }

        assertArrayEquals(tv.k, MLKEMApplet.secretKey, "Shared secret mismatch for vector " + tv.tcId);
        assertArrayEquals(tv.c, MLKEMApplet.bufC, "Ciphertext mismatch for vector " + tv.tcId);
    }

    /**
     * This function loads the test vectors from the JSON file
     * @param filename name of the JSON file
     * @param parameterSet specific parameter (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @return list of test vectors
     */
    private List<EncapsTestVector> loadTestVectorsFromJSON(String filename, String parameterSet, String function) {
        List<EncapsTestVector> vectors = new ArrayList<>();

        try (InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename)) {
            if (inputStream == null) {
                fail("Test vector file not found: " + filename);
                return vectors;
            }

            JSONTokener tokener = new JSONTokener(new InputStreamReader(inputStream));
            JSONObject root = new JSONObject(tokener);
            JSONArray testGroups = root.getJSONArray("testGroups");

            for (int i = 0; i < testGroups.length(); i++) {
                JSONObject testGroup = testGroups.getJSONObject(i);
                String groupParameterSet = testGroup.optString("parameterSet", "");
                String groupFunction = testGroup.optString("function", "");

                if (!parameterSet.equals(groupParameterSet) || !function.equals(groupFunction)) {
                    continue;
                }

                JSONArray tests = testGroup.getJSONArray("tests");
                for (int j = 0; j < tests.length(); j++) {
                    JSONObject test = tests.getJSONObject(j);
                    EncapsTestVector tv = new EncapsTestVector();
                    tv.tcId = test.getInt("tcId");
                    tv.parameterSet = groupParameterSet;
                    tv.dk = hexToBytes(test.getString("dk"));
                    tv.m = hexToBytes(test.getString("m"));
                    tv.k = hexToBytes(test.getString("k"));
                    tv.c = hexToBytes(test.getString("c"));
                    vectors.add(tv);
                }
            }

            System.out.println("Loaded " + vectors.size() + " test vectors from " + filename + " for " + parameterSet + " / " + function);

        } catch (Exception e) {
            fail("Exception reading test vectors: " + e.getMessage());
        }

        return vectors;
    }

    /**
     * Tranforms the hexadecimal numbers in the test vector to the byte format
     * @param hex the hexadecimal string
     * @return the byte equivalent
     */
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }
}
