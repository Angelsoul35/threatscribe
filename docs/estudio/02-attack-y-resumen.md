# 02 — ATT&CK y el resumen

## Etiquetado ATT&CK: un lookup, no un clasificador

MITRE ATT&CK es un catálogo de técnicas de adversarios (p. ej. T1566 Phishing,
T1059.001 PowerShell, T1486 Ransomware). threatscribe etiqueta el informe mapeando
**frases** que suelen aparecer ("spear-phishing", "powershell", "scheduled task",
"ransomware", "command and control", "public-facing") a su técnica. Cada etiqueta
guarda la **frase exacta** que la disparó.

Es un **lookup curado, no un clasificador**, a propósito:

- **Transparente:** el analista ve exactamente por qué se etiquetó una técnica
  (la frase evidencia), y puede rechazarla.
- **Sin datos de entrenamiento, fácil de ampliar:** añadir cobertura es añadir una
  frase revisada por un humano, no reentrenar.
- **Riguroso en su rol:** cada etiqueta está respaldada por una frase del texto,
  así que es **verificable**; es una ayuda de primera pasada, no un mapeo
  autoritativo que reemplace al analista.

Un clasificador aprendido sería opaco, necesitaría un dataset etiquetado que no
existe de forma estable, y podría etiquetar técnicas sin base en el texto.

## El resumen: LLM + respaldo extractivo

El resumen es la **única** salida asistida por LLM. ¿Por qué solo aquí? Porque es
donde la fluidez ayuda de verdad y donde un error es de bajo riesgo (lo lee una
persona). El `Summarizer` pide a la cascada de proveedores un resumen de 2-3
frases.

Pero el tool debe correr **offline** (pruebas, SOC aislado, proveedor caído). Por
eso hay un **respaldo extractivo determinista**: puntúa cada frase por posición
(bonus a la primera) y por densidad de vocabulario de amenaza ("ransomware",
"exploit", "campaign"...) y devuelve las más salientes. Cada resumen marca su
`source` (`llm` o `extractive`).

El resumen es una **comodidad**; los IOC y las etiquetas son la salida
autoritativa, y no dependen del LLM en ningún caso.

## Para fijar la idea

- ATT&CK por mapa de palabras clave con evidencia: transparente, ampliable, ayuda
  de primera pasada (no reemplaza al analista).
- El LLM solo para el resumen, donde la fluidez ayuda y el error es de bajo riesgo.
- Respaldo extractivo determinista → siempre hay resumen, offline; marca su fuente.
