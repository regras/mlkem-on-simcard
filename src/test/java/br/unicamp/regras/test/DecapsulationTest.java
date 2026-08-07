package br.unicamp.regras.test;

import br.unicamp.regras.applet.MLKEMApplet;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

public class DecapsulationTest {

    static class DecapsTestVector {
        int tcId;
        byte[] dk;
        byte[] c;
        byte[] k;
    }

    /**
     * Executes the decapsulation test for ML-KEM-512 parameter set.
     */
    @Test
    public void testDecapsulation512() {
        runDecapsulationSuite("ML-KEM-512", (short) 1);
    }

    /**
     * Executes the decapsulation test for ML-KEM-768 parameter set.
     */
    @Test
    public void testDecapsulation768() {
        runDecapsulationSuite("ML-KEM-768", (short) 3);
    }

    /**
     * Executes the decapsulation test for ML-KEM-1024 parameter set.
     */
    @Test
    public void testDecapsulation1024() {
        runDecapsulationSuite("ML-KEM-1024", (short) 5);
    }

    /**
     * This test method executes the decapsulation algorithm in the specific level
     * @param parameterSet The parameter set to test (e.g., "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024").
     * @param level The security level to test.
     */
    private void runDecapsulationSuite(String parameterSet, short level) {
        List<DecapsTestVector> vectors = loadTestVectorsFromJSON(parameterSet);

        assertFalse(vectors.isEmpty(), "No test vectors loaded for " + parameterSet + " from internalProjectionDecaps.json");

        int successCount = 0;
        for (DecapsTestVector tv : vectors) {
            try {
                runDecapsulationVector(tv, level);
                successCount++;
            } catch (AssertionError e) {
                fail("Test vector " + tv.tcId + " failed for " + parameterSet + ": " + e.getMessage());
            }
        }

        System.out.println("DecapsulationTest: Successfully tested " + successCount + " test vectors for " + parameterSet);
    }

    /**
     * This method tests key generation for a specific parameter set using the provided test vector.
     * It initializes the MLKEMApplet with the given level, sets the packedDK from the test vector, and performs decapsulation.
     * It then asserts that the generated shared secret matches the expected value from the test vector.
     *
     @param tv The test vector containing d, z, expected public key, and expected secret key.
     @param level The parameter set to test (e.g., "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024").
     */
    private void runDecapsulationVector(DecapsTestVector tv, short level) {
        new MLKEMApplet(level);

        MLKEMApplet.packedDK = tv.dk.clone();
        MLKEMApplet.bufC = tv.c.clone();

        byte[] message = new byte[32];
        switch (level) {
            case 1:
            case 2:
                MLKEMApplet.decaps512Internal(message);
                break;
            case 3:
                MLKEMApplet.decaps768Internal(message);
                break;
            case 5:
                MLKEMApplet.decaps1024Internal(message);
                break;
            default:
                fail("Unsupported ML-KEM level: " + level);
        }

        assertArrayEquals(tv.k, MLKEMApplet.secretKey, "Shared secret mismatch for vector " + tv.tcId);
    }

    /**
     * This function loads the test vectors from the JSON file
     * @param parameterSet specific parameter (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @return list of test vectors
     */
    private List<DecapsTestVector> loadTestVectorsFromJSON(String parameterSet) {
        List<DecapsTestVector> vectors = new ArrayList<>();

        try (InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("internalProjectionDecaps.json")) {
            if (inputStream == null) {
                fail("Test vector file not found: internalProjectionDecaps.json");
                return vectors;
            }

            JSONTokener tokener = new JSONTokener(new InputStreamReader(inputStream));
            JSONObject root = new JSONObject(tokener);
            JSONArray testGroups = root.getJSONArray("testGroups");

            for (int i = 0; i < testGroups.length(); i++) {
                JSONObject testGroup = testGroups.getJSONObject(i);
                String groupParameterSet = testGroup.optString("parameterSet", "");
                String groupFunction = testGroup.optString("function", "");

                if (!parameterSet.equals(groupParameterSet) || !"decapsulation".equals(groupFunction)) {
                    continue;
                }

                JSONArray tests = testGroup.getJSONArray("tests");
                for (int j = 0; j < tests.length(); j++) {
                    JSONObject test = tests.getJSONObject(j);
                    DecapsTestVector tv = new DecapsTestVector();
                    tv.tcId = test.getInt("tcId");
                    tv.dk = hexToBytes(test.getString("dk"));
                    tv.c = hexToBytes(test.getString("c"));
                    tv.k = hexToBytes(test.getString("k"));
                    vectors.add(tv);
                }
            }

            System.out.println("Loaded " + vectors.size() + " test vectors from internalProjectionEncapsDecaps.json for " + parameterSet + " / decapsulation");

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
