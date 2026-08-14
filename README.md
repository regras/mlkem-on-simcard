# Implementation and evaluation of the post-quantum algorithm ML-KEM on smart cards

This repository contains the implementation of the ML-KEM post-quantum key encapsulation algorithm, designed to run on smart cards, such as SIMs and eSIMs.

The goal is to provide a secure and efficient cryptography solution for resource-constrained devices, using optimization techniques to bypass memory and processing limitations.

This work was carried out by Fernando A. Penido, supervised by Marco A. Henriques and assisted by Caio Teixeira and Rodrigo D. Meneses, in the undergraduate research program at Unicamp, with support from the Coordenação Coordenação de Aperfeiçoamento de Pessoal de Nível Superior (CAPES) and the Conselho Nacional de Desenvolvimento Científico e Técnologico (CNPq).

**Abstract:** This paper implements and evaluates the post-quantum key encapsulation mechanism ML-KEM on the Java Card platform, specifically targeting SIM and eSIM cards.
To achieve this goal, on-the-fly vector generation and global buffers are used to address memory and performance restrictions in these environments.
The achieved memory footprint enables the deployment of ML-KEM on resource-constrained cards with less than 7 kB of RAM, further driving the adoption of post-quantum cryptography in mobile networks.
# README.md structure and repository organization

This repository contains a README.md file detailing the project's structure, including information about the organization of directories and files, security considerations, as well as instructions for installation, running tests, and experiments.
The sections are outlined below:

* [Implementation and evaluation of the post-quantum algorithm ML-KEM on smart cards](#implementation-and-evaluation-of-the-post-quantum-algorithm-ml-kem-on-smart-cards)
* [README.md structure and repository organization](#readmemd-structure-and-repository-organization)
* [Considered Badges](#considered-badges)
* [Basic Information](#basic-information)
* [Dependencies](#dependencies)
* [Security Concerns](#security-concerns)
* [Installation](#installation)
* [Minimal Test](#minimal-test)
* [Experiments](#experiments)
* [Claim #1: Algorithm Correctness (NIST Tests)](#claim-1-algorithm-correctness-nist-tests)
* [Claim #2: Memory Consumption](#claim-2-memory-consumption)
* [Claim #3: Applet Execution Time](#claim-3-applet-execution-time)
* [LICENSE](#license)

The repository is organized as follows:
```text
mlkem-on-simcard/
├── src/
│   ├── main/java/br/unicamp/ic/mlkem/
│   │   └── MLKEMApplet.java              # Main logic of the ML-KEM algorithm for Java Card
│   │
│   └── test/
│       ├── java/br/unicamp/ic/mlkem/
│       │   ├── DecapsulationTest.java    # Validation of decapsulation against NIST vectors
│       │   ├── EncapsulationTest.java    # Validation of encapsulation against NIST vectors
│       │   ├── KeyGenerationTest.java    # Validation of key generation against NIST vectors
│       │   └── Time_MLKEMApplet.java     # Simulated execution time benchmark for the MLKEMApplet
│       │   └── Time_KyberJCE.java        # Simulated execution time benchmark for the KyerJCE
│       │   └───KyberJCE                  # KyberJCE package used as the basis for the ML-KEM implementation
│       │       ├───interfaces
│       │       │       KyberKey.java
│       │       │       KyberPrivateKey.java
│       │       │       KyberPublicKey.java
│       │       │
│       │       ├───provider
│       │       │   │   Kyber1024KeyPairGenerator.java
│       │       │   │   Kyber512KeyPairGenerator.java
│       │       │   │   Kyber768KeyPairGenerator.java
│       │       │   │   KyberCipherText.java
│       │       │   │   KyberDecrypted.java
│       │       │   │   KyberEncrypted.java
│       │       │   │   KyberJCE.java
│       │       │   │   KyberKeyAgreement.java
│       │       │   │   KyberKeyFactory.java
│       │       │   │   KyberKeySize.java
│       │       │   │   KyberPackedPKI.java
│       │       │   │   KyberParameterGenerator.java
│       │       │   │   KyberPKI.java
│       │       │   │   KyberPrivateKey.java
│       │       │   │   KyberPublicKey.java
│       │       │   │   KyberSecretKey.java
│       │       │   │   KyberUniformRandom.java
│       │       │   │   KyberVariant.java
│       │       │   │
│       │       │   └───kyber
│       │       │           ByteOps.java
│       │       │           Indcpa.java
│       │       │           KyberParams.java
│       │       │           Ntt.java
│       │       │           Poly.java
│       │       │           UnpackedCipherText.java
│       │       │           UnpackedPublicKey.java
│       │       │
│       │       ├───spec
│       │       │       KyberGenParameterSpec.java
│       │       │       KyberParameterSpec.java
│       │       │       KyberPrivateKeySpec.java
│       │       │       KyberPublicKeySpec.java
│       │       │
│       │       └───util
│       │               DerEncoder.java
│       │               DerIndefLenConverter.java
│       │               DerInputBuffer.java
│       │               DerInputStream.java
│       │               DerOutputStream.java
│       │               DerValue.java
│       │               KyberKeyUtil.java
│       │               ObjectIdentifier.java
│       │
│       └── resources/
│           ├── internalProjectionDecaps.json  # Raw NIST Known Answer Tests (KATs)
│           ├── internalProjectionEncaps.json  # Raw NIST Known Answer Tests (KATs)
│           └── internalProjectionKeyGen.json  # Raw NIST Known Answer Tests (KATs)
│       
│       
├── pom.xml                               # Dependency manager (Maven, jCardSim, JUnit)
└── README.md                             # Artifact evaluation documentation
```
Due to the overhead that multiple classes and objects introduce, as described in the article, the entire ML-KEM logic is present in a single class.
To facilitate the visualization and understanding of the code, each execution logic was separated by a comment separator, which describes the type of the following operations.
Among the types, are these:

- **Standard Java Card Functions (lines 245-443)**: Standard Java Card functions, such as applet installation, selection, and APDU command processing.
- **SHAKE and SHA3 (lines 444-919)**: SHAKE and SHA3 hash functions, used to generate pseudo-random arrays from seeds.
- **NTT Operations (lines 920-1,038)**: Number Theoretic Transform (NTT) functions, used to accelerate polynomial operations.
- **Polynomial Operations (lines 1,039-1,519)**: Functions for polynomial manipulation, including addition, subtraction, multiplication, and reduction.
- **Byte Operations (lines 1,520-1,605)**: Functions for byte manipulation, including byte-to-int conversion and vice versa.
- **Indistinguishability under Chosen Plaintext Attack (IND-CPA) (lines 1,606-2,203)**: Functions for key generation, key encapsulation, and decapsulation, ensuring security against chosen plaintext attacks.

The test execution can be seen in the video:
[[Test Execution Video]](https://youtu.be/pJ3oR3Wf7vg)

# Considered Badges

The badges considered for evaluation are: Available Artifacts (SeloD), Functional Artifacts (SeloF), Sustainable/Reusable Artifacts (SeloS), and Reproducible Experiments (SeloR).

# Basic Information

To execute the artifact, only a desktop environment and the installation of the dependencies described in the section below are required.

The artifact was developed and tested in a Linux environment, but it can also be run on Windows and MacOS systems, provided the dependencies are correctly installed.

No specific hardware, such as smart cards, is required to execute the artifact, because the applet is executed in a Java Card simulator (jCardSim) that simulates the behavior of a smart card in a desktop environment.

As a recommendation, we have the following minimum specifications for the execution environment:

**Hardware Requirements:**
- Processor: Modern x86_64 or ARM architecture
- RAM Memory: 2 GB
- Disk Space: 500 MB

**Software Requirements:**
- Operating System: Linux, Windows, or MacOS
- Java Development Kit (JDK): Version 17
- Apache Maven: Version 3.11.0
- Internet access to download Maven dependencies

# Dependencies

To execute the artifact, the following dependencies are required:

| Dependency             | Version     | Need in the Project                                                                                                   | Installation |
|:-----------------------|:------------|:----------------------------------------------------------------------------------------------------------------------| :--- |
| **JDK**                | 17          | Base Java execution and compilation environment required to run the project.                                          | Manual |
| **Apache Maven**       | 3.11.0      | Dependency manager and build automation, responsible for compiling and running the tests.                             | Manual |
| **jCardSim**\*         | 3.0.6.0     | Java Card API simulator that allows running and testing the applet on the desktop without a physical smart card.        | Automatic |
| **org.json**\*         | 20231013    | Required to read, parse, and process the JSON files containing the NIST test vectors (KATs).                          | Automatic |
| **JUnit 5**\*          | 5.10.0      | Testing framework used to structure, automate, and validate the tests.                | Automatic |
| **JMH**\*              | 1.37        | Framework used to benchmark the MLKEMApplet and KyberJCE                                                              | Automatic |
| **keccakj**\*          | 1.1.0       | Used to execute the SHAKE functions in the KyberJCE implementation                                                    | Automatic |

\* These dependencies do not require prior manual installation. They are automatically downloaded and configured by Maven when the test command is executed.

# Security Concerns

This code poses no risk to the reviewers, however, it is important to note that the code has been altered to facilitate the testing process.
Specifically, the test class used is br.unicamp.regras.applet.MLKEMApplet, which is a version of the MLKEMApplet with exposed test methods to allow the validation of the results obtained with the NIST test vectors.

Consequently, an applet with the correct privacy access was created within the br.unicamp.regras.sec_app package to allow the applet's execution in practical cases.

The list of exposed functions/buffers for testing purposes within br.unicamp.regras.applet.MLKEMApplet is as follows:
- `packedDK` (byte[]) - buffer that stores the decapsulation key.
- `secretKey` (byte[]) - buffer that stores the secret key.
- `bufC` (byte[]) - buffer that stores the encapsulation.
- `generateKeys512Internal()` - internal key generation function for ML-KEM-512.
- `generateKeys768Internal()` - internal key generation function for ML-KEM-768.
- `generateKeys1024Internal()` - internal key generation function for ML-KEM-1024.
- `generateKeys512()` - function that generates the key pair for ML-KEM-512.
- `generateKeys768()` - function that generates the key pair for ML-KEM-768.
- `generateKeys1024()` - function that generates the key pair for ML-KEM-1024.
- `encaps512Internal()` - internal function for encapsulating the secret key for ML-KEM-512.
- `encaps768Internal()` - internal function for encapsulating the secret key for ML-KEM-768.
- `encaps1024Internal()` - internal function for encapsulating the secret key for ML-KEM-1024.
- `encaps512()` - function that encapsulates the ML-KEM-512 secret key.
- `encaps768()` - function that encapsulates the ML-KEM-768 secret key.
- `encaps1024()` - function that encapsulates the ML-KEM-1024 secret key.
- `decaps512Internal()` - internal function for decapsulating the ML-KEM-512 secret key.
- `decaps768Internal()` - internal function that decapsulates the ML-KEM-768 secret key.
- `decaps1024Internal()` - internal function that decapsulates the ML-KEM-1024 secret key.
- `decaps512()` - function that decapsulates the ML-KEM-512 secret key.
- `decaps768()` - function that decapsulates the ML-KEM-768 secret key.
- `decaps1024()` - function that decapsulates the ML-KEM-1024 secret key.

# Installation

To install the artifact, you need to install the required dependencies.
Next, clone the repository and access the project directory.

```bash
# Update the package list
sudo apt-get update

# Install JDK 17, Maven and Git
sudo apt-get install -y git maven openjdk-17-jdk

# Clone the artifact repository
git clone https://github.com/regras/mlkem-on-simcard

# Access the project directory
cd mlkem-on-simcard
```
# Minimal Test

The minimal test consists of running the applet's correctness tests, which validate the ML-KEM key generation, encapsulation, and decapsulation against the NIST Known Answer Tests (KATs).

To execute it, simply run the command below, after installing the dependencies and cloning the repository.

```bash
mvn clean compile
```

In case the dependencies are not correctly installed, the command will fail, and an error message will be displayed, indicating the missing dependencies.

# Experiments

This section describes a step-by-step guide for executing and obtaining the results from the article.
Reviewers should be able to achieve the presented claims.

## Claim #1: Algorithm Correctness (NIST Tests)

This claim is validated by the applet's correctness tests, which compare the obtained results with the NIST test vectors (KATs).
The execution of the correctness tests is performed by the command below:
```bash
mvn clean test -q | tee log_testes_funcionais.txt
```
This command runs the ML-KEM key generation, encapsulation, and decapsulation tests.
A success message is expected to appear at the end of the execution, indicating that all tests have passed.

If an error occurs, the user should check if the dependencies have the correct version and if there was any alterations to the original file.   

The test results are saved in the `log_testes_funcionais.txt` file, which contains the complete test output, including success or failure messages for each test.

## Claim #2: Memory Consumption

The memory consumption of the applet is a static code evaluation of all the memory allocations.
Due to the allocations being solely executed in the ``install`` method, which calls the ``MLKEMApplet()`` constructor, this analysis is a simple sum of all allocations.

So, the memory consumption of the applet's `MLKEMApplet()` function is available below:

```java
    public MLKEMApplet(short level) {
    // SHAKE allocation buffers: In total, 407 (bytes) are allocated
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
    bufNoise = transientShortArray(paramsN); // 256 shorts (512 bytes)
    bufMatrix = transientShortArray(paramsN); // 256 shorts (512 bytes)
    bufPolyTemp = transientShortArray(paramsN); // 256 shorts (512 bytes)
    hashBuffer = transientByteArray(672); // 672 bytes
    seedBuf = transientByteArray(64); // 64 bytes
    sr = RandomData.getInstance(RandomData.ALG_KEYGENERATION); // consumes virtually zero bytes (resource pre-allocated by the JCRE)
    secretKey = transientByteArray(MLKEMSSBytes);  // 32 bytes
    message = transientByteArray(32); // 32 bytes

    if (level == 1 || level == 2) {
        // ML-KEM-512
        packedDK = new byte[MLKEM512SKBytes]; // 1623 bytes
        bufC = transientByteArray(MLKEM512CTBytes); // 768 bytes
        bufCRed = transientByteArray(MLKEM512CTBytes); // 768 bytes
    }
    if (level == 3) {
        // ML-KEM-768
        packedDK = new byte[MLKEM768SKBytes]; // 2400 bytes
        bufC = transientByteArray(MLKEM768CTBytes); // 1088 bytes
        bufCRed = transientByteArray(MLKEM768CTBytes); // 1088 bytes
    }
    if (level == 5) {
        // ML-KEM-1024
        packedDK = new byte[MLKEM1024SKBytes]; // 3168 bytes
        bufC = transientByteArray(MLKEM1024CTBytes); // 1568 bytes
        bufCRed = transientByteArray(MLKEM1024CTBytes); // 1568 bytes
    }
}
```
From this function, it is possible to observe that the memory consumption of the applet is equivalent to Table 2, presented in the article, which is the sum of all allocations of the `MLKEMApplet()` constructor.

This table is reproduced below, with the detailed memory consumption for each ML-KEM security level.

<table>
  <thead>
    <tr>
      <th>Level</th>
      <th>Operation</th>
      <th>RAM (B)</th>
      <th>Flash (B)</th>
      <th>Total (B)</th>
    </tr>
  </thead>
  <tbody>
    <!-- ML-KEM-512 Block -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-512</strong></td>
      <td>Key Generation</td>
      <td>2,679</td>
      <td>1,623</td>
      <td>4,302</td>
    </tr>
    <tr>
      <td>Encapsulation</td>
      <td>3,447</td>
      <td>1,655</td>
      <td>5,102</td>
    </tr>
    <tr>
      <td>Decapsulation</td>
      <td>4,215</td>
      <td>1,655</td>
      <td>5,870</td>
    </tr>
    <!-- ML-KEM-768 Block -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-768</strong></td>
      <td>Key Generation</td>
      <td>2,679</td>
      <td>2,400</td>
      <td>5,079</td>
    </tr>
    <tr>
      <td>Encapsulation</td>
      <td>3,767</td>
      <td>2,432</td>
      <td>6,199</td>
    </tr>
    <tr>
      <td>Decapsulation</td>
      <td>4,855</td>
      <td>2,432</td>
      <td>7,287</td>
    </tr>
    <!-- ML-KEM-1024 Block -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-1024</strong></td>
      <td>Key Generation</td>
      <td>2,679</td>
      <td>3,168</td>
      <td>5,847</td>
    </tr>
    <tr>
      <td>Encapsulation</td>
      <td>4,247</td>
      <td>3,200</td>
      <td>7,447</td>
    </tr>
    <tr>
      <td>Decapsulation</td>
      <td>5,815</td>
      <td>3,200</td>
      <td>9,015</td>
    </tr>
  </tbody>
</table>

## Claim #3: Applet Execution Time

To perform the execution time benchmark, it is necessary to run the command below, which will compile the project and execute the benchmark using the JMH framework.
The execution time in milliseconds for key generation, encapsulation, and decapsulation for the MLKEMApplet and KyberJCE will be displayed, allowing a comparison between the two implementations.

```bash
# Run the execution time benchmarks
mvn test-compile exec:exec -Dexec.executable="java" -Dexec.classpathScope="test" -Dexec.args="-cp %classpath org.openjdk.jmh.Main -rf csv -rff resultados_benchmark.csv"
```

The result will be available in the `resultados_benchmark.csv` file, which contains the execution times in microseconds for each operation of the MLKEMApplet and KyberJCE.

The JMH framework does not guarantee identical results for each run, so it is expected that the results will vary between executions.
Furthermore, different execution environments may present different times, so it is important to analyze the ratios between the execution of the MLKEMApplet and KyberJCE, which should be consistent with the results presented in the article.

The result of this work is described in Table 4 of the article, reproduced below:
<table>
  <thead>
    <tr>
      <th>Level</th>
      <th>Operation</th>
      <th>KyberJCE (ms/op)</th>
      <th>This Work (ms/op)</th>
      <th>Ratio*</th>
    </tr>
  </thead>
  <tbody>
    <!-- ML-KEM-512 Block -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-512</strong></td>
      <td>Key Generation</td>
      <td>0.17 ± 0.01</td>
      <td>1.41 ± 0.15</td>
      <td>8.67</td>
    </tr>
    <tr>
      <td>Encapsulation</td>
      <td>0.07 ± 0.01</td>
      <td>1.53 ± 0.31</td>
      <td>21.33</td>
    </tr>
    <tr>
      <td>Decapsulation</td>
      <td>0.08 ± 0.01</td>
      <td>1.85 ± 0.20</td>
      <td>24.08</td>
    </tr>
    <!-- ML-KEM-768 Block -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-768</strong></td>
      <td>Key Generation</td>
      <td>0.20 ± 0.01</td>
      <td>2.26 ± 0.05</td>
      <td>11.48</td>
    </tr>
    <tr>
      <td>Encapsulation</td>
      <td>0.10 ± 0.01</td>
      <td>2.37 ± 0.49</td>
      <td>23.00</td>
    </tr>
    <tr>
      <td>Decapsulation</td>
      <td>0.12 ± 0.03</td>
      <td>2.76 ± 0.11</td>
      <td>23.59</td>
    </tr>
    <!-- ML-KEM-1024 Block -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-1024</strong></td>
      <td>Key Generation</td>
      <td>0.25 ± 0.03</td>
      <td>3.60 ± 0.30</td>
      <td>14.48</td>
    </tr>
    <tr>
      <td>Encapsulation</td>
      <td>0.17 ± 0.08</td>
      <td>3.89 ± 0.16</td>
      <td>22.45</td>
    </tr>
    <tr>
      <td>Decapsulation</td>
      <td>0.16 ± 0.02</td>
      <td>4.66 ± 0.42</td>
      <td>28.94</td>
    </tr>
  </tbody>
</table>

\* The ratio column is not extracted during the JMH testing, only after the data results. 

# LICENSE

This project is licensed under the MIT License. Full details can be found in the `LICENSE` file at the root of this repository, which also includes the copyright notices and attributions to the ThothTrust and KyberJCE projects used as a basis for this implementation.