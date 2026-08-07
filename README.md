# Implementação e avaliação do algoritmo pós-quântico ML-KEM em smart cards
Este repositório contém a implementação do algoritmo pós-quântico de encapsulamento de chaves ML-KEM, desenvolvido para ser executado em smart cards, como SIMs e eSIMs. 
O objetivo é fornecer uma solução de criptografia segura e eficiente para dispositivos com recursos limitados, utilizando técnicas de otimização para contornar restrições de memória e processamento.
Este trabalho foi realizado por Fernando A. Penido, orientado por Marco A. Henriques e auxiliado por Caio Teixeira e Rodrigo D. Meneses, no programa de iniciação científica da Unicamp, com apoio da Coordenação de Aperfeiçoamento de Pessoal de Nível Superior (CAPES) e do Conselho Nacional de Desenvolvimento Científico e Tecnológico (CNPq).

**Resumo:** Este artigo implementa e avalia o algoritmo pós-quântico de encapsulamento de chaves ML-KEM na plataforma Java Card, especificamente visando SIMs e eSIMs como as plataformas finais.
Para tal fim, são utilizadas técnicas de otimização como buffers globais e geração de vetores sob demanda para contornar limitações de memória e processamento nesses ambientes restritos.
O consumo de memória alcançado permite implementar o ML-KEM em cartões com recursos restritos e menos de 7 kB de RAM, impulsionando ainda mais a adoção da criptografia pós-quântica em redes móveis.

Resumo descrevendo o objetivo do artefato, com o respectivo título e resumo do artigo[cite: 1].
(DICA: Cole aqui o abstract do artigo detalhando o uso de buffers globais e geração sob demanda para contornar restrições de memória[cite: 2].)

# Estrutura do readme.md

Este repositório contém um arquivo README.md detalhando a estrutura do projeto, incluindo informações sobre a organização dos diretórios e arquivos, considerações de segurança, bem como instruções para instalação, execução de testes e experimentos.

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
│       │
│       └── resources/
│           ├── internalProjectionDecaps.json  # Known Answer Tests (KATs) brutos do NIST
│           ├── internalProjectionEncaps.json  # Known Answer Tests (KATs) brutos do NIST
│           └── internalProjectionKeyGen.json  # Known Answer Tests (KATs) brutos do NIST
│
├── pom.xml                               # Gerenciador de dependências (Maven, jCardSim, JUnit)
└── README.md                             # Documentação de avaliação do artefato
```
# Selos Considerados

Os selos considerados para avaliação são: Artefatos Disponíveis (SeloD), Artefatos Funcionais (SeloF), Artefatos Sustentáveis (SeloS) e Experimentos Reprodutíveis (SeloR).

# Informações básicas

Esta seção deve apresentar informações básicas de todos os componentes necessários para a execução e replicação dos experimentos[cite: 1]. Descrevendo todo o ambiente de execução, com requisitos de hardware e software[cite: 1].
(DICA: Especifique que a execução requer apenas um ambiente desktop, utilizando o simulador jCardSim via máquina virtual Java[cite: 2].)

# Dependências

Informações relacionadas a benchmarks utilizados e dependências para a execução devem ser descritas nesta seção[cite: 1]. Busque deixar o mais claro possível, apresentando informações como versões de dependências e processos para acessar recursos de terceiros caso necessário[cite: 1].
(DICA: Liste o JDK 17, o Apache Maven, o jCardSim (3.0.5), a biblioteca org.json (20231013) e o JUnit 5 (5.10.0).)

# Preocupações com segurança

Esse código não apresenta nenhum risco para os avaliadores, porém, é importante ressaltar que o código foi alterado para facilitar o processo de testes.
Portanto, os métodos de geração de chaves, encapsulamento e desencapsulamento foram alterados para permitir a injeção de vetores de teste do NIST.
Além disso, buffers como 'packedDK' (a chave de desencapsulamento) e 'secretKey' (a chave secreta) foram expostos para permitir a validação dos resultados.

Ressalta-se que, para a utilização do artefato em casos práticos, É NECESSÁRIO REVERTER ESSAS ALTERAÇÕES. 

# Instalação

O processo de baixar e instalar a aplicação deve ser descrito nesta seção[cite: 1]. Ao final deste processo já é esperado que a aplicação/benchmark/ferramenta consiga ser executada[cite: 1].
(DICA: Coloque os comandos de `git clone` do repositório e o `mvn clean install` para o download automatizado das dependências.)

# Teste mínimo

Esta seção deve apresentar um passo a passo para a execução de um teste mínimo[cite: 1]. Um teste mínimo de execução permite que os revisores consigam observar algumas funcionalidades do artefato[cite: 1].
(DICA: Apresente o comando `mvn test` indicando como o avaliador pode visualizar no terminal o sucesso da execução dos testes básicos.)

# Experimentos

Esta seção deve descrever um passo a passo para a execução e obtenção dos resultados do artigo[cite: 1]. Permitindo que os revisores consigam alcançar as reivindicações apresentadas no artigo[cite: 1]. Cada reivindicações deve ser apresentada em uma subseção, com detalhes de arquivos de configurações a serem alterados, comandos a serem executados, flags a serem utilizadas, tempo esperado de execução, expectativa de recursos a serem utilizados como 1GB RAM/Disk e resultado esperado[cite: 1].

## Reivindicação #1: Corretude do Algoritmo (Testes NIST)
(DICA: Mostre como rodar a validação que atesta que o Applet produz as chaves esperadas usando os KATs[cite: 2].)

## Reivindicação #2: Consumo de Memória
(DICA: Explique como os scripts/benchmarks comprovam a redução do consumo de memória RAM e Flash que foi detalhada nas tabelas do artigo[cite: 2].)

# LICENSE

Este projeto está licenciado sob a Licença MIT. Detalhes completos podem ser encontrados no arquivo `LICENSE` na raiz deste repositório, que também inclui os avisos de direitos autorais e atribuições aos projetos ThothTrust e KyberJCE utilizados como base para esta implementação.