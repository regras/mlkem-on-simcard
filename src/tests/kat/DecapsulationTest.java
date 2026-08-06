package com.swiftcryptollc.crypto.provider;

import com.swiftcryptollc.crypto.applet.MLKEMApplet;
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

    @Test
    public void testDecapsulation512() {
        runDecapsulationSuite("ML-KEM-512", (short) 1);
    }

    @Test
    public void testDecapsulation768() {
        runDecapsulationSuite("ML-KEM-768", (short) 3);
    }

    @Test
    public void testDecapsulation1024() {
        runDecapsulationSuite("ML-KEM-1024", (short) 5);
    }

    private void runDecapsulationSuite(String parameterSet, short level) {
        List<DecapsTestVector> vectors = loadTestVectorsFromJSON(parameterSet);

        assertFalse(vectors.isEmpty(), "No test vectors loaded for " + parameterSet + " from internalProjectionEncapsDecaps.json");

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

    private List<DecapsTestVector> loadTestVectorsFromJSON(String parameterSet) {
        List<DecapsTestVector> vectors = new ArrayList<>();

        try (InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("assets/internalProjectionEncapsDecaps.json")) {
            if (inputStream == null) {
                fail("Test vector file not found: internalProjectionEncapsDecaps.json");
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

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }
}
