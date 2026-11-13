# GENItool

CLI para reunir **Nmap, fuzzing de caminhos HTTP, Wappalyzer e possíveis CVEs da NVD** em um relatório `.txt`, acompanhado de checksum SHA-256. Use em sistemas próprios ou dentro de um escopo de penteste autorizado.

Veja um [relatório gerado contra um servidor local de teste](examples/README.md).

## O que faz

- **Nmap:** enumera as portas TCP solicitadas com `-sT -sV --version-light -Pn` e interpreta XML, incluindo produtos, versões e CPEs. Não precisa de root.
- **Fuzzing nativo:** testa uma wordlist por GET, calibra respostas de caminhos inexistentes para descartar soft 404/catch-all e repete os candidatos para verificar se a observação é reproduzível.
- **Wappalyzer real:** utiliza o engine e as assinaturas do pacote `wappalyzer@6.10.66` sobre HTML, metadados, URLs de scripts e cabeçalhos coletados. A análise é estática: não executa JavaScript nem busca recursos externos.
- **CVEs:** consulta a API NVD 2.0 quando encontra uma versão. Prefere CPE com versão; usa produto + versão como alternativa explicitamente menos precisa. Todos os resultados são **candidatos a validação**, inclusive correspondências por CPE.
- **TXT:** registra evidências, estados das etapas e falhas; grava também `.txt.sha256`. Uma falha de ferramenta não apaga os resultados das outras etapas.

“Validação dos resultados” significa repetir a observação e registrar a evidência. SHA-256 permite detectar alterações quando comparado a um checksum confiável; não constitui assinatura digital nem prova de autoria.

## Instalação

Requisitos: Python 3.10+, Nmap no `PATH` e, para Wappalyzer, Node.js 18+ e npm.

```bash
git clone https://github.com/AndreMTavolassi/GENItool.git
cd GENItool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .

# Dependência opcional de detecção de tecnologias:
npm install --ignore-scripts
export GENITOOL_WAPPALYZER_DIR="$PWD/node_modules/wappalyzer"

genitool doctor
```

Em Debian/Ubuntu, instale o Nmap pelo gerenciador do sistema (`sudo apt install nmap`). Em macOS, pode usar `brew install nmap`.

O pacote Python não exige bibliotecas de terceiros. Também pode executar direto do checkout com `python3 -m genitool`, sem instalar o pacote Python. A variável `GENITOOL_WAPPALYZER_DIR` deve apontar para o diretório do pacote Wappalyzer quando ele estiver fora da árvore do pacote Python instalado.

**Limitação do Wappalyzer:** a versão npm 7 é um pacote vazio, portanto esta integração fixa a última versão anterior com engine utilizável e identifica suas assinaturas históricas no relatório. Tecnologias novas e tecnologias que dependem de JavaScript podem não ser identificadas. O modo `--ignore-scripts` evita o download desnecessário do Chromium; o adaptador não usa Puppeteer.

## Uso

```bash
genitool scan https://seu-alvo.example -o resultado.txt
```

Com configuração de portas e wordlist:

```bash
genitool scan http://127.0.0.1:8080/app/ \
  --ports 22,80,443,8080 \
  --wordlist genitool/data/paths.txt \
  --max-paths 100 --rate 5 \
  --timeout 10 --scan-timeout 120 \
  --max-cve-queries 5 \
  -o resultado.txt
```

Sem `-o`, grava em `reports/<host>_<data-UTC>.txt`. Um hostname ou IP sem esquema usa HTTPS. Para um caminho base, informe a URL completa. IPv6 deve estar entre colchetes na URL, por exemplo `http://[::1]:8080/`.

O Nmap analisa o host nas portas solicitadas; o caminho base limita o fuzzing HTTP. O conjunto padrão usa portas comuns e inclui a porta explícita da URL. Não há descoberta automática de subdomínios, CIDRs ou listas de hosts. Cada execução recebe um único alvo. Redirecionamentos HTTP, inclusive para HTTPS ou login, são registrados sem serem seguidos; informe a URL final autorizada para analisá-la.

Para executar somente o fuzzing, por exemplo:

```bash
genitool scan http://127.0.0.1:8080/ \
  --skip-nmap --skip-wappalyzer --skip-cves -o caminhos.txt
```

Opções independentes: `--skip-nmap`, `--skip-wappalyzer`, `--skip-fuzz`, `--skip-cves`. Consulte `genitool scan --help`.

## Áreas autenticadas

O cliente aceita credenciais existentes via headers. Ele não realiza login nem força senhas. No Bash, é possível ler um token sem colocá-lo no histórico:

```bash
read -r -s -p 'Token: ' GENITOOL_TOKEN
export GENITOOL_TOKEN
genitool scan https://seu-alvo.example -o autenticado.txt
unset GENITOOL_TOKEN
```

`GENITOOL_TOKEN` gera `Authorization: Bearer ...`; `GENITOOL_COOKIE` permite informar um cookie de sessão. Para outros esquemas, crie um arquivo JSON local:

```json
{
  "Authorization": "Bearer SEU_TOKEN",
  "Cookie": "session=SEU_COOKIE"
}
```

```bash
chmod 600 headers.json
genitool scan https://seu-alvo.example --headers-file headers.json -o autenticado.txt
```

As variáveis de ambiente têm precedência sobre Authorization/Cookie do arquivo. Headers não são enviados ao Nmap, à NVD nem a outra origem. Seus valores são removidos do relatório e não aparecem nos argumentos dos subprocessos. O relatório informa que headers foram fornecidos; isso não comprova que o servidor aceitou a sessão. Respostas 401/403 são evidências de controle de acesso, não de vulnerabilidade.

## Consulta de CVEs

A consulta NVD é habilitada por padrão quando há fingerprints com versão. Sem versões observadas, ela é ignorada com uma nota. A NVD recebe os identificadores de produto/versão consultados. O padrão limita a cinco consultas e até vinte resultados por consulta; `--max-cve-queries` permite de 1 a 100. Os resultados podem ser incompletos: não há paginação exaustiva.

Sem chave, o cliente espaça consultas em pelo menos 6,1 segundos. Uma chave opcional em `NVD_API_KEY` reduz o intervalo para 0,7 segundo. Falhas, limitação HTTP 429 e indisponibilidade da NVD aparecem no TXT; não se convertem em “nenhuma CVE”. Distribuições podem aplicar correções sem mudar a versão anunciada: confira os avisos do fornecedor antes de concluir que uma CVE afeta o alvo.

## Evidências, limites e integridade

- A wordlist padrão contém 21 caminhos; você pode fornecer outra. O máximo padrão é 100 caminhos e o limite superior é 10.000. Entradas com traversal, URLs absolutas, query ou fragmento são rejeitadas.
- O fuzzing faz até `2 + 2 × max_paths` requisições, incluindo calibração e revalidação. `--rate` limita todas essas requisições; não limita os probes TCP do Nmap. HTTP 429 interrompe o fuzzing.
- Os corpos HTTP são limitados a 1 MiB e não são gravados no relatório. O TXT registra o hash dos bytes capturados. Capturas truncadas não são tratadas como observações validadas.
- `--timeout` limita operações de socket e há checagem adicional durante a leitura do corpo. Não é um limite absoluto para DNS ou cabeçalhos enviados lentamente. `--scan-timeout` limita o processo Nmap e as operações do estágio Wappalyzer.
- TLS é verificado. Páginas dinâmicas podem produzir observações instáveis; ausência de achados não comprova ausência de vulnerabilidades.
- Em sistemas POSIX, os relatórios são gravados com permissão `0600`. Ctrl+C preserva os resultados das etapas já concluídas em um relatório parcial.

```bash
genitool verify resultado.txt
# Alternativa em Linux, no diretório do relatório:
sha256sum -c resultado.txt.sha256
```

Códigos de saída: `0` = etapas concluídas ou desativadas explicitamente; `1` = execução incompleta/erro de etapa ou checksum divergente; `2` = erro de configuração/arquivo; `130` = interrompido. Uma dependência solicitada ausente produz relatório e código `1`.

## Testes

```bash
python3 -m unittest discover -s tests -v
```

Os testes usam servidores HTTP locais e respostas NVD simuladas. Cobrem isolamento de credenciais, redirecionamentos, soft 404, revalidação, limites, XML Nmap, classificação de CVEs, redação de segredos e integridade do relatório. O teste do engine real Wappalyzer roda quando a dependência opcional está instalada.

Licença MIT.
