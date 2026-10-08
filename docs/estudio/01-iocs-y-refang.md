# 01 — IOCs, defang y refang

## Qué es un IOC

Un IOC (indicator of compromise, indicador de compromiso) es un dato observable
que delata actividad maliciosa: una IP de C2, un dominio, una URL de descarga, el
hash de un fichero, un correo de phishing, un CVE explotado, una dirección de
Bitcoin de rescate. Un SOC los necesita en formato **máquina** para bloquearlos y
cazarlos.

## Defang y refang

Los informes "desarman" (defang) los indicadores para que no se puedan clicar ni
resolver por accidente:

- `hxxps://evil[.]com` en vez de `https://evil.com`
- `8[.]8[.]8[.]8` en vez de `8.8.8.8`
- `user[at]evil[dot]com` en vez de `user@evil.com`

Un extractor ingenuo que corra sus regex sobre el texto crudo **se pierde** justo
esos indicadores. Por eso threatscribe hace **refang primero**: deshace los
esquemas comunes (`hxxp`→`http`, `[.]`→`.`, `[at]`→`@`, `[dot]`→`.`, `[:]`→`:`) y
luego extrae. Así, un indicador desarmado se extrae igual que uno normal, y sale
en forma canónica lista para un blocklist.

## Extracción determinista y cuidadosa

La extracción es por **expresiones regulares**, con dos sutilezas que la hacen
correcta y no ingenua:

1. **Orden por longitud en hashes:** se buscan primero SHA256 (64 hex), luego SHA1
   (40), luego MD5 (32), saltando los ya capturados. Así un SHA256 no se parte en
   dos "MD5" falsos.
2. **Dominios al final:** se saltan los que ya están dentro de una URL o un correo
   ya capturados, para no duplicar.

La deduplicación es insensible a mayúsculas. Resultado: el **mismo informe da
siempre el mismo conjunto de IOC**, auditable.

## ¿Por qué determinista y no un modelo?

Porque un feed de IOC tiene un requisito duro: **exactitud y reproducibilidad**.
Un feed que a veces se pierde un indicador real deja puntos ciegos; uno que
inventa indicadores hace perder cazas y puede causar bloqueos erróneos. Un modelo
probabilístico puede hacer ambas cosas. Una regex no inventa una IP que no está en
el texto. El fallo correcto de un feed es "me perdí uno" (una brecha conocida que
se cierra con una regla nueva), no "me inventé uno" (un error silencioso que
destruye la confianza).

## Para fijar la idea

- IOC = dato observable de ataque; el SOC los quiere en formato máquina.
- Refang antes de extraer, o te pierdes los indicadores desarmados.
- Extracción por regex, ordenada y deduplicada → determinista y auditable.
- Determinista a propósito: un feed debe ser exacto y reproducible, no "listo".
