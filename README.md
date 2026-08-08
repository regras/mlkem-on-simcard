# Implementação e avaliação do algoritmo pós-quântico ML-KEM em smart cards
Este repositório contém a implementação do algoritmo pós-quântico de encapsulamento de chaves ML-KEM, desenvolvido para ser executado em smart cards, como SIMs e eSIMs. 

O objetivo é fornecer uma solução de criptografia segura e eficiente para dispositivos com recursos limitados, utilizando técnicas de otimização para contornar restrições de memória e processamento.

Este trabalho foi realizado por Fernando A. Penido, orientado por Marco A. Henriques e auxiliado por Caio Teixeira e Rodrigo D. Meneses, no programa de iniciação científica da Unicamp, com apoio da Coordenação de Aperfeiçoamento de Pessoal de Nível Superior (CAPES) e do Conselho Nacional de Desenvolvimento Científico e Tecnológico (CNPq).

**Resumo:** Este artigo implementa e avalia o algoritmo pós-quântico de encapsulamento de chaves ML-KEM na plataforma Java Card, especificamente visando SIMs e eSIMs como as plataformas finais.
Para tal fim, são utilizadas técnicas de otimização como buffers globais e geração de vetores sob demanda para contornar limitações de memória e processamento nesses ambientes restritos.
O consumo de memória alcançado permite implementar o ML-KEM em cartões com recursos restritos e menos de 7 kB de RAM, impulsionando ainda mais a adoção da criptografia pós-quântica em redes móveis.

# Estrutura do readme.md e organização do repositório

Este repositório contém um arquivo README.md detalhando a estrutura do projeto, incluindo informações sobre a organização dos diretórios e arquivos, considerações de segurança, bem como instruções para instalação, execução de testes e experimentos.
As seções estão separadas abaixo:

* [Implementação do ML-KEM em smart cards](#implementação-e-avaliação-do-algoritmo-pós-quântico-ml-kem-em-smart-cards)
* [Estrutura do readme.md e organização do repositório](#estrutura-do-readmemd-e-organização-do-repositório)
* [Selos Considerados](#selos-considerados)
* [Informações básicas](#informações-básicas)
* [Dependências](#dependências)
* [Preocupações com segurança](#preocupações-com-segurança)
* [Instalação](#instalação)
* [Teste mínimo](#teste-mínimo)
* [Experimentos](#experimentos)
* [Reivindicação #1: Corretude do Algoritmo (Testes NIST)](#reivindicação-1-corretude-do-algoritmo-testes-nist)
* [Reivindicação #2: Consumo de Memória](#reivindicação-2-consumo-de-memória)
* [Reivindicação #3: Tempo de execução do Applet](#reivindicação-3-tempo-de-execução-do-applet)
* [LICENSE](#license)

O repositório está organizado da seguinte forma:
```text
mlkem-on-simcard/
├── src/
│   ├── main/java/br/unicamp/ic/mlkem/
│   │   └── MLKEMApplet.java              # Lógica principal do algoritmo ML-KEM para Java Card
│   │
│   └── test/
│       ├── java/br/unicamp/ic/mlkem/
│       │   ├── DecapsulationTest.java    # Validação do desencapsulamento contra vetores NIST
│       │   ├── EncapsulationTest.java    # Validação do encapsulamento contra vetores NIST
│       │   ├── KeyGenerationTest.java    # Validação da geração de chaves contra vetores NIST
│       │   └── TimeTest_MLKEMApplet.java # Benchmark simulado de tempo de execução
│       │   └───KyberJCE                  # Pacote do KyberJCE utilizado como base para a implementação do ML-KEM
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
│           ├── internalProjectionDecaps.json  # Known Answer Tests (KATs) brutos do NIST
│           ├── internalProjectionEncaps.json  # Known Answer Tests (KATs) brutos do NIST
│           └── internalProjectionKeyGen.json  # Known Answer Tests (KATs) brutos do NIST
│       
│       
├── pom.xml                               # Gerenciador de dependências (Maven, jCardSim, JUnit)
└── README.md                             # Documentação de avaliação do artefato
```
Devido à sobrecarga que múltiplas classes e objetos introduzem, como descrito no artigo, a lógica inteira do ML-KEM está presente em uma só classe. 
Para facilitar a visualização e compreensão do código, foram separadas cada lógica de execução por um separador de comentários, que descreve qual o tipo das operações seguintes.
Dentres os tipos, estão esses:

- **Funções Padrão do Java Card (linhas 245-443)**: Funções padrão do Java Card, como instalação do Applet, seleção e processamento de comandos APDU.
- **SHAKE e SHA3 (linhas 444-919)**: Funções de hash SHAKE e SHA3, utilizadas para gerar vetores pseudo-aleatórios a partir de sementes.
- **Operações de NTT (linhas 920-1.038)**: Funções de Transformada Rápida de Número Inteiro (NTT), utilizadas para acelerar operações polinomiais.
- **Operações Polinomiais (linhas 1.039-1.519)**: Funções para manipulação de polinômios, incluindo adição, subtração, multiplicação e redução.
- **Operações de Byte (linhas 1.520-1.605)**: Funções para manipulação de bytes, incluindo conversão de byte para int e vice-versa.
- **Indistiguibilidade sob Ataque de Texto Claro Escolhido (IND-CPA) (linhas 1.606-2.203)**: Funções para geração de chaves, encapsulamento e desencapsulamento de chaves, garantindo segurança contra ataques de texto escolhido.
# Selos Considerados

Os selos considerados para avaliação são: Artefatos Disponíveis (SeloD), Artefatos Funcionais (SeloF), Artefatos Sustentáveis (SeloS) e Experimentos Reprodutíveis (SeloR).

# Informações básicas

Para a execução do artefato, é necessário apenas um ambiente desktop e a instalação das dependências descritas na seção abaixo. 

O artefato foi desenvolvido e testado em um ambiente Linux, mas também pode ser executado em sistemas Windows e MacOS, desde que as dependências sejam corretamente instaladas.

Não é necessário nenhum hardware específico, como smart cards, para a execução do artefato, pois o Applet é executado em um simulador de Java Card (jCardSim) que simula o comportamento de um smart card em um ambiente desktop.

Como recomendação, temos as seguintes especificações mínimas para o ambiente de execução:

**Requisitos de Hardware:**
- Processador: Arquitetura x86_64 ou ARM moderna
- Memória RAM: 2 GB
- Espaço em disco: 500 MB

**Requisitos de Software:**
- Sistema Operacional: Linux, Windows ou MacOS
- Java Development Kit (JDK): Versão 17
- Apache Maven: Versão 3.11.0
- Acesso à internet para baixar dependências do Maven

# Dependências

Para a execução do artefato, são necessárias as seguintes dependências:

| Dependência            | Versão      | Necessidade no Projeto                                                                                                | Instalação |
|:-----------------------|:------------|:----------------------------------------------------------------------------------------------------------------------| :--- |
| **JDK**                | 17          | Ambiente de execução e compilação base do Java necessário para rodar o projeto.                                       | Manual |
| **Apache Maven**       | 3.11.0      | Gerenciador de dependências e automação de build, responsável por compilar e rodar os testes.                         | Manual |
| **jCardSim**\*         | 3.0.6.0     | Simulador da API Java Card que permite executar e testar o Applet no desktop sem um smart card físico.                | Automática |
| **org.json**\*         | 20231013    | Necessária para ler, fazer o parse e processar os arquivos JSON contendo os vetores de teste (KATs) do NIST.          | Automática |
| **JUnit 5**\*          | 5.10.0      | Framework de testes utilizado para estruturar, automatizar e validar os testes de encapsulamento e desencapsulamento. | Automática |
| **JMH**\*              | 1.37        | Framework utilizado para realizar o Benchamrk do MLKEMApplet e KyberJCE                                               | Automática |
| **keccakj**\*          | 1.1.0       | Utilizado para executar as funções SHAKE na implementação KyberJCE                                                    | Automática |

\* Estas dependências não exigem instalação manual prévia. Elas são baixadas e configuradas automaticamente pelo Maven no momento da execução do comando de testes.

# Preocupações com segurança

Esse código não apresenta nenhum risco para os avaliadores, porém, é importante ressaltar que o código foi alterado para facilitar o processo de testes.
Em específico, a implementação de teste utilizada é a br.unicamp.regras.applet.MLKEMApplet, que é uma versão do MLKEMApplet com métodos de teste expostos para permitir a validação dos resultados obtidos com os vetores de teste do NIST.

Em consequência, foi criado um applet com os acessos de privacidade corretos dentro do pacote br.unicamp.regras.sec_app para permitir a execução do applet em casos práticos.

A lista de funções/buffers expostos para fins de teste dentro do br.unicamp.regras.applet.MLKEMApplet é a seguinte:
- `packedDK` (byte[]) - buffer que armazena a chave de desencapsulamento.
- `secretKey` (byte[]) - buffer que armazena a chave secreta.
- `bufC` (byte[]) - buffer que armazena o encapsulamento.
- `generateKeys512Internal()` - função que gera o par de chaves ML-KEM.
- `generateKeys768Internal()` - função que gera o par de chaves ML-KEM.
- `generateKeys1024Internal()` - função que gera o par de chaves ML-KEM.
- `generateKeys512()` - função que gera o par de chaves ML-KEM.
- `generateKeys768()` - função que gera o par de chaves ML-KEM.
- `generateKeys1024()` - função que gera o par de chaves ML-KEM.
- `encaps512Internal()` - função que encapsula a chave secreta.
- `encaps768Internal()` - função que encapsula a chave secreta.
- `encaps1024Internal()` - função que encapsula a chave secreta.
- `encaps512()` - função que encapsula a chave secreta.
- `encaps768()` - função que encapsula a chave secreta.
- `encaps1024()` - função que encapsula a chave secreta.
- `decaps512Internal()` - função que desencapsula a chave secreta.
- `decaps768Internal()` - função que desencapsula a chave secreta.
- `decaps1024Internal()` - função que desencapsula a chave secreta.
- `decaps512()` - função que desencapsula a chave secreta.
- `decaps768()` - função que desencapsula a chave secreta.
- `decaps1024()` - função que desencapsula a chave secreta.

# Instalação

Para a instalação do artefato, é necessário instalar as dependências requeridas. 
Em seguida, clonar o repositório e acessar o diretório do projeto. 

```bash
# Atualizar a lista de pacotes
sudo apt-get update

# Instalar o JDK 17, Maven e Git
sudo apt-get install -y git maven openjdk-17-jdk

# Clonar o repositório do artefato
git clone https://github.com/regras/mlkem-on-simcard.git

# Acessar o diretório do projeto
cd mlkem-on-simcard
```

# Teste mínimo

O teste mínimo consiste em executar os testes de corretude do Applet, que validam a geração de chaves, encapsulamento e desencapsulamento do ML-KEM contra os vetores de teste (KATs) do NIST.

Para sua execução, basta executar o comando abaixo, após a instalação das dependências e clonagem do repositório.

```bash
mvn clean test | tee log_testes_funcionais.txt
```

# Experimentos

Esta seção descreve um passo a passo para a execução e obtenção dos resultados do artigo. 
Os revisores devem conseguir alcançar as reivindicações apresentadas.

## Reivindicação #1: Corretude do Algoritmo (Testes NIST)

Essa reivindicação é validada pelos testes de corretude do Applet, que comparam os resultados obtidos com os vetores de teste (KATs) do NIST.
A execução dos testes de corretude é realizada pelo comando `mvn clean test`, que executa os testes de geração de chaves, encapsulamento e desencapsulamento do ML-KEM.
É esperado que apareça uma mensagem de sucesso ao final da execução, indicando que todos os testes foram aprovados.

## Reivindicação #2: Consumo de Memória

O consumo de memória do Applet é simplesmente a soma de todas as alocações do construtor `MLKEMApplet()`, que é executado apenas uma vez durante a chamada do método `install()` (método da instalação do Applet no smart card).


A função `MLKEMApplet()` do Applet está disponível abaixo:
```java
    public MLKEMApplet(short level) {
    // SHAKE allocation buffers: Ao todo, são alocados 407 (bytes)
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
    sr = RandomData.getInstance(RandomData.ALG_KEYGENERATION); // gasta virtualmente zero bytes (recurso pré-alocado pela JCRE)
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

Por essa função, é possível observar que o consumo de memória do Applet é equivalente a Tabela 2, apresentada no artigo, que é a soma de todas as alocações do construtor `MLKEMApplet()`.

Essa tabela está reproduzida abaixo, com o consumo de memória detalhado para cada nível de segurança do ML-KEM.


<table>
  <thead>
    <tr>
      <th>Nível</th>
      <th>Operação</th>
      <th>RAM (B)</th>
      <th>Flash (B)</th>
      <th>Total (B)</th>
    </tr>
  </thead>
  <tbody>
    <!-- Bloco ML-KEM-512 -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-512</strong></td>
      <td>Geração de Chaves</td>
      <td>2.679</td>
      <td>1.623</td>
      <td>4.302</td>
    </tr>
    <tr>
      <td>Encapsulamento</td>
      <td>3.447</td>
      <td>1.655</td>
      <td>5.102</td>
    </tr>
    <tr>
      <td>Desencapsulamento</td>
      <td>4.215</td>
      <td>1.655</td>
      <td>5.870</td>
    </tr>
    <!-- Bloco ML-KEM-768 -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-768</strong></td>
      <td>Geração de Chaves</td>
      <td>2.679</td>
      <td>2.400</td>
      <td>5.079</td>
    </tr>
    <tr>
      <td>Encapsulamento</td>
      <td>3.767</td>
      <td>2.432</td>
      <td>6.199</td>
    </tr>
    <tr>
      <td>Desencapsulamento</td>
      <td>4.855</td>
      <td>2.432</td>
      <td>7.287</td>
    </tr>
    <!-- Bloco ML-KEM-1024 -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-1024</strong></td>
      <td>Geração de Chaves</td>
      <td>2.679</td>
      <td>3.168</td>
      <td>5.847</td>
    </tr>
    <tr>
      <td>Encapsulamento</td>
      <td>4.247</td>
      <td>3.200</td>
      <td>7.447</td>
    </tr>
    <tr>
      <td>Desencapsulamento</td>
      <td>5.815</td>
      <td>3.200</td>
      <td>9.015</td>
    </tr>
  </tbody>
</table>

## Reivindicação #3: Tempo de execução do Applet

Para realizar o benchmark do tempo de execução, é necessário executar o comando abaixo, que irá compilar o projeto e executar o benchmark utilizando o framework JMH.
Será exibido o tempo de execução em microssegundos para a geração de chaves, encapsulamento e desencapsulamento do MLKEMApplet e do KyberJCE, permitindo a comparação entre as duas implementações.

```bash
# Executar os benchmarks de tempo de execução
mvn test-compile exec:exec -Dexec.executable="java" -Dexec.classpathScope="test" -Dexec.args="-cp %classpath org.openjdk.jmh.Main -rf csv -rff resultados_benchmark.csv"
```

O framework JMH não garante execução com resultados idênticos para cada execução, portanto, é esperado que os resultados variem entre execuções.
Além disso, diferentes ambientes de execução podem apresentar tempos diferentes, assim é importante analisar as proporções entre a execução do MLKEMApplet e do KyberJCE, que devem ser consistentes com os resultados apresentados no artigo.

O resultado do trabalho está descrito na Tabela 4 do artigo, reproduzida abaixo:
<table>
  <thead>
    <tr>
      <th>Nível</th>
      <th>Operação</th>
      <th>KyberJCE (ms/op)</th>
      <th>Este Trabalho (ms/op)</th>
      <th>Razão</th>
    </tr>
  </thead>
  <tbody>
    <!-- Bloco ML-KEM-512 -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-512</strong></td>
      <td>Geração de Chaves</td>
      <td>0,17 ± 0,01</td>
      <td>1,41 ± 0,15</td>
      <td>8,67</td>
    </tr>
    <tr>
      <td>Encapsulamento</td>
      <td>0,07 ± 0,01</td>
      <td>1,53 ± 0,31</td>
      <td>21,33</td>
    </tr>
    <tr>
      <td>Desencapsulamento</td>
      <td>0,08 ± 0,01</td>
      <td>1,85 ± 0,20</td>
      <td>24,08</td>
    </tr>
    <!-- Bloco ML-KEM-768 -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-768</strong></td>
      <td>Geração de Chaves</td>
      <td>0,20 ± 0,01</td>
      <td>2,26 ± 0,05</td>
      <td>11,48</td>
    </tr>
    <tr>
      <td>Encapsulamento</td>
      <td>0,10 ± 0,01</td>
      <td>2,37 ± 0,49</td>
      <td>23,00</td>
    </tr>
    <tr>
      <td>Desencapsulamento</td>
      <td>0,12 ± 0,03</td>
      <td>2,76 ± 0,11</td>
      <td>23,59</td>
    </tr>
    <!-- Bloco ML-KEM-1024 -->
    <tr>
      <td rowspan="3"><strong>ML-KEM-1024</strong></td>
      <td>Geração de Chaves</td>
      <td>0,25 ± 0,03</td>
      <td>3,60 ± 0,30</td>
      <td>14,48</td>
    </tr>
    <tr>
      <td>Encapsulamento</td>
      <td>0,17 ± 0,08</td>
      <td>3,89 ± 0,16</td>
      <td>22,45</td>
    </tr>
    <tr>
      <td>Desencapsulamento</td>
      <td>0,16 ± 0,02</td>
      <td>4,66 ± 0,42</td>
      <td>28,94</td>
    </tr>
  </tbody>
</table>

# LICENSE

Este projeto está licenciado sob a Licença MIT. Detalhes completos podem ser encontrados no arquivo `LICENSE` na raiz deste repositório, que também inclui os avisos de direitos autorais e atribuições aos projetos ThothTrust e KyberJCE utilizados como base para esta implementação.