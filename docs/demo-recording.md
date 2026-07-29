# Gravando o GIF de demo do `yubel scan` (macOS)

Um GIF curto (10–20s) do scan rodando é o que mais aumenta engajamento num post. Aqui vai o caminho mais limpo, com `asciinema` (grava o terminal como texto, leve) + `agg` (converte pra GIF).

## 1) Instalar as ferramentas

```bash
brew install asciinema agg
```

## 2) Preparar o terminal (pra ficar bonito)

- Deixe a janela num tamanho tipo **100×28** (colunas × linhas). Nem muito larga, nem alta demais.
- Tema escuro combina com a marca. Fonte um pouco maior ajuda na leitura do GIF.
- Feche abas/coisas que possam poluir a captura.

## 3) Gravar

```bash
# começa a gravar (vai criar demo.cast)
asciinema rec demo.cast

# ... agora rode um scan curto e visual. Sugestão de roteiro abaixo ...

# quando terminar, encerra a gravação:
exit        # (ou Ctrl+D)
```

### Roteiro sugerido (curto e com payoff visual)

Use um alvo público **que você tem permissão de escanear** — os alvos de treino da OWASP servem (ex.: `testphp.vulnweb.com`, `demo.testfire.net`). Rode em modo rápido pra não demorar:

```bash
yubel --version
yubel scan -t http://testphp.vulnweb.com --fast --fail-on high -o out
```

O `--fast` deixa o scan enxuto. O payoff bom pro GIF é a **tela final**: o resumo executivo com grade A–F, contagem de findings corroborados/cadeias/sistêmicos. Se o scan real demorar demais pra um GIF, você pode:

- gravar só o **começo** (banner + engines subindo) e o **resumo final**, e cortar o meio; ou
- rodar o `yubel selftest -o out` (scan sintético, sem rede, rápido) só pra mostrar a saída e o relatório — é instantâneo e sempre dá certo.

## 4) Converter pra GIF

```bash
agg demo.cast yubel-demo.gif
```

Opções úteis (opcionais):

```bash
# tema e velocidade
agg --theme monokai --speed 1.3 --font-size 20 demo.cast yubel-demo.gif
```

- `--speed 1.3` acelera um pouco (bom se teve pausas).
- `--font-size` maior = mais legível em telas pequenas.

## 5) Usar no post

- **LinkedIn:** anexa o GIF direto (ele reproduz no feed).
- **X/Twitter:** anexa no 1º tweet da thread.
- **README:** dá pra colocar também — commita `docs/logo/yubel-demo.gif` e referencia com URL absoluta:
  ```html
  <p align="center">
    <img src="https://raw.githubusercontent.com/ggeorgeazevedo/yubel/main/docs/logo/yubel-demo.gif" alt="Yubel scan demo" width="820">
  </p>
  ```

## Dica

Se quiser algo ainda mais controlado (sem depender do tempo real do scan), dá pra gravar um **screen-record** normal do macOS (`Cmd+Shift+5`), rodar o scan, e depois converter o `.mov` pra GIF com `ffmpeg`:

```bash
brew install ffmpeg
ffmpeg -i demo.mov -vf "fps=12,scale=900:-1:flags=lanczos" yubel-demo.gif
```

Mas o `asciinema + agg` costuma dar o resultado mais limpo e leve pra terminal.
