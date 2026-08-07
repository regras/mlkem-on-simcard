package br.unicamp.regras.test;

import br.unicamp.regras.applet.MLKEMApplet;

import org.openjdk.jmh.annotations.*;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.MICROSECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.MICROSECONDS)
@Fork(2)
public class TimeTest_MLKEMApplet {
    private MLKEMApplet applet;
    private byte[] aliceGeneratedSecretKey;
    private byte[] bobGeneratedSecretKey;
    String hex512 = "19C44D35AB9EF31B1360F0BF33CF63D80E405962D698415C5888F0AF385DCFF4";
    byte[] seed512 = java.util.HexFormat.of().parseHex(hex512);
    short[] poly = new short[256];

    @Param({"512", "768", "1024"})
    private int securityLevel;

    /**
     * Sets the configuration of the Applet and initializes it
     */
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

    /**
     * Marks the time for the key generation process.
     * @return true (to avoid JMH optimizations that might skip the method)
     */
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

    /**
     * Marks the time for the encapsulation process.
     * @return true (to avoid JMH optimizations that might skip the method)
     */
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

    /**
     * Marks the time for the decapsulation process.
     * @return true (to avoid JMH optimizations that might skip the method)
     */
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

    public static void main(String[] args) throws Exception {
        org.openjdk.jmh.runner.options.Options opt = new org.openjdk.jmh.runner.options.OptionsBuilder()
                // Pega todos os @Benchmark dentro de MLKEMBenchmark
                .include(TimeTest_MLKEMApplet.class.getSimpleName() + ".keyGen")
                .include(TimeTest_MLKEMApplet.class.getSimpleName() + ".encaps")
                .include(TimeTest_MLKEMApplet.class.getSimpleName() + ".decaps")
                .build();
        new org.openjdk.jmh.runner.Runner(opt).run();
    }
}
