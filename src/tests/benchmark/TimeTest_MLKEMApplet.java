package com.swiftcryptollc.crypto.provider;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import com.swiftcryptollc.crypto.applet.MLKEMApplet;

import static org.junit.jupiter.api.Assertions.*;
import org.openjdk.jmh.annotations.*;
import java.util.concurrent.TimeUnit;

// Configurações do JMH
@BenchmarkMode(Mode.AverageTime) // Queremos medir o tempo médio de execução
@OutputTimeUnit(TimeUnit.MICROSECONDS) // O resultado será em microsegundos
@State(Scope.Thread) // Mantém o estado isolado por thread
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS) // Tempo para a JVM otimizar
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS) // Medição real
@Fork(2) // Roda em uma JVM separada para garantir isolamento
public class KeyAgreementJMH {
    private MLKEMApplet applet;
    private byte[] aliceGeneratedSecretKey;
    private byte[] bobGeneratedSecretKey;
    String hex512 = "19C44D35AB9EF31B1360F0BF33CF63D80E405962D698415C5888F0AF385DCFF4";
    byte[] seed512 = java.util.HexFormat.of().parseHex(hex512);
    short[] poly = new short[256];

    @Param({"512", "768", "1024"})
    private int securityLevel;

    @Setup(Level.Trial)
    public void setupApplet() {
        aliceGeneratedSecretKey = new byte[32];
        bobGeneratedSecretKey = new byte[32];
        // O valor de 'securityLevel' JÁ ESTÁ INJETADO AQUI!
        // Agora você instancia a classe com os arrays do tamanho exato.

        switch (securityLevel) {
            case 512:
                // Se o construtor receber o tamanho:
                // applet = new MLKEMApplet((short) 512);

                // Ou se forem classes diferentes:
                applet = new MLKEMApplet((short) 2);
                break;

            case 768:
                applet = new MLKEMApplet((short) 3);
                break;

            case 1024:
                applet = new MLKEMApplet((short) 5);
                break;

            default:
                throw new IllegalStateException("Nível de segurança inválido!");
        }
    }

    @Benchmark
    public boolean keyGen(){
        switch(securityLevel){
            case 512:
                MLKEMApplet.generateKeys512();
                break;
            case 768:
                MLKEMApplet.generateKeys768();
                break;
            case 1024:
                MLKEMApplet.generateKeys1024();
                break;
            default:
                throw new IllegalStateException("Nível de segurança inválido!");
        }
        return true;
    }

    @Benchmark
    public boolean encaps(){
        switch (securityLevel) {
            case 512:
                MLKEMApplet.encapsulation512();
                break;
            case 768:
                MLKEMApplet.encapsulation768();
                break;
            case 1024:
                MLKEMApplet.encapsulation1024();
                break;
            default:
                throw new IllegalStateException("Nível de segurança inválido!");
        }
        return true;
    }

    @Benchmark
    public boolean decaps(){
        switch (securityLevel) {
            case 512:
                MLKEMApplet.decapsulation512();
                break;
            case 768:
                MLKEMApplet.decapsulation768();
                break;
            case 1024:
                MLKEMApplet.decapsulation1024();
                break;
            default:
                throw new IllegalStateException("Nível de segurança inválido!");
        }
        return true;
    }

    @Benchmark
    public boolean generatePoly(){
        MLKEMApplet.getNoisePoly(seed512, (short) 0, (byte) 2, 3, poly, (short) 0);
        return (poly[1] == 0);
    }

    @Benchmark
    public boolean generateMatrixTest(){
        MLKEMApplet.generateMatrix(seed512, false, 3, (short) 0, (short) 1, poly);
        return (poly[1] == 0);
    }

    public static void main(String[] args) throws Exception {
        org.openjdk.jmh.runner.options.Options opt = new org.openjdk.jmh.runner.options.OptionsBuilder()
                // Pega todos os @Benchmark dentro de MLKEMBenchmark
                .include(KeyAgreementJMH.class.getSimpleName() + ".generatePoly")
                .include(KeyAgreementJMH.class.getSimpleName() + ".generateMatrixTest")
                .param("securityLevel", "512")
                .build();
        new org.openjdk.jmh.runner.Runner(opt).run();
    }
}
