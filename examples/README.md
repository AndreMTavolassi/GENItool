# Relatório de exemplo

`relatorio-local.txt` foi gerado em uma integração real com Nmap 7.93, o engine Wappalyzer 6.10.66 e o fuzzing do GENItool, contra um servidor HTTP de teste em loopback.

O servidor simulava HTML WordPress e um cabeçalho Nginx para testar os fingerprints; esses produtos não estavam instalados no alvo. Um token fictício foi utilizado para validar a passagem de credenciais sem registrá-las. A etapa de CVEs foi desativada nesse exemplo. A porta é temporária e o servidor já foi encerrado.

Para conferir o arquivo, execute na raiz do projeto:

```bash
python3 -m genitool verify examples/relatorio-local.txt
```
