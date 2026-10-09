# 03 — Preguntas de entrevista

Preguntas típicas sobre este proyecto y cómo responderlas con seguridad.
Practica diciéndolas en voz alta en inglés también.

## Sobre el diseño

**¿Por qué la extracción es determinista y solo el resumen usa LLM?**
Porque un feed de IOC debe ser exacto y reproducible: perder un indicador real
deja puntos ciegos e inventar uno hace perder cazas o causa bloqueos erróneos. Un
modelo puede hacer ambas; una regex no inventa. El LLM se reserva al resumen, donde
la fluidez ayuda y el error es de bajo riesgo porque lo lee una persona, y además
con respaldo extractivo offline.

**¿Qué es el refang y por qué importa?**
Los informes desarman los indicadores (`hxxp`, `[.]`, `[at]`) para que no se
cliquen. Si extraigo sobre el texto crudo, me pierdo justo esos. Hago refang
primero (deshago los esquemas) y luego extraigo; así se capturan y salen en forma
canónica.

## Sobre la extracción

**¿Cómo evitas que un SHA256 se cuente como dos MD5?**
Busco los hashes por longitud, primero SHA256 (64 hex), luego SHA1 (40), luego MD5
(32), saltando los ya capturados. Y los dominios al final, saltando los que ya
están dentro de una URL o correo. Todo deduplicado sin importar mayúsculas.

## Sobre ATT&CK

**¿Por qué un mapa de palabras clave y no un clasificador?**
Porque debe ser transparente (cada etiqueta muestra la frase que la disparó),
ampliable sin reentrenar, y verificable: cada etiqueta queda anclada a una frase,
así que es una ayuda de primera pasada, no un mapeo autoritativo. Un clasificador
sería opaco y necesitaría datos etiquetados que no existen de forma estable.

## Sobre robustez

**¿Qué pasa si no hay LLM?**
La extracción y el etiquetado no lo usan nunca, así que no cambian. El resumen cae
al modo extractivo determinista. El tool corre entero offline.

## Pregunta trampa

**Tu mapa de palabras clave se pierde técnicas descritas con otras palabras. ¿No
es una limitación?**
Sí, y es el fallo correcto: una técnica no etiquetada es una brecha visible que se
cierra añadiendo una frase revisada; preferible a un modelo opaco que etiqueta con
confianza pero sin explicación. Y como cada etiqueta muestra su evidencia, el
analista detecta sobre-etiquetado al instante. Transparente y ampliable gana a
ingenioso y opaco para una ayuda de analista.
