# Guía de estudio — threatscribe

Esta carpeta es una guía en español para entender threatscribe a fondo. El código,
los comentarios y la documentación técnica están en inglés (nivel B2) a propósito,
para que el proyecto sea creíble y sirva para practicar. Esta guía explica el "por
qué" de cada decisión en tu idioma.

## Orden sugerido de lectura

1. **[01-iocs-y-refang.md](01-iocs-y-refang.md)** — qué son los IOC, el "defang" y
   el "refang", y por qué la extracción es determinista.
2. **[02-attack-y-resumen.md](02-attack-y-resumen.md)** — el etiquetado ATT&CK por
   palabras clave y el resumen con LLM + respaldo extractivo.
3. **[03-preguntas-de-entrevista.md](03-preguntas-de-entrevista.md)** — preguntas
   típicas y cómo responderlas con seguridad.
4. **[04-validacion-datos-reales.md](04-validacion-datos-reales.md)** — la
   validación sobre 6.000 CVE reales: estructura y fórmula CVSS, las métricas
   (precision/recall/F1, baseline), sobre/infraajuste, held-out y validación
   cruzada, el control de sanidad, y un ejemplo trabajado con números reales.

## Resumen en una frase

threatscribe convierte un informe de inteligencia de amenazas en texto libre en
salida estructurada — los IOC (refanged y deduplicados), las técnicas MITRE ATT&CK
(por mapa de palabras clave, con evidencia) y un resumen — con extracción y
etiquetado deterministas y el LLM reservado solo para el resumen, con respaldo
extractivo offline.
