# 04 — Validación con datos reales (CVE + CVSS)

Este capítulo explica cómo validamos los motores **deterministas** de threatscribe
sobre **datos reales**: 6.000 CVE reales (años 2016–2023) del dataset público
`harinpurumandla/cve-severity-dataset` en Hugging Face. Cada registro es una
descripción real de la NVD junto con su **vector CVSS v3.1** de verdad. El informe
completo se genera, sin red, con:

```bash
python -m threatscribe.real_benchmark
```

La idea de fondo: un informe de amenazas cita CVE, y el **vector CVSS es la
afirmación legible por máquina de lo que hace ese CVE**. Así que el vector es la
*verdad de terreno* (ground truth) contra la que medimos la salida estructurada.

---

## 1. La estructura CVSS v3.1

Un vector base tiene ocho métricas, cada una un código de una letra. Ejemplo:
`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`.

| Métrica | Significado | Valores |
| ------- | ----------- | ------- |
| **AV** Attack Vector | por dónde se explota | N(etwork), A(dyacente), L(ocal), P(hysical) |
| **AC** Attack Complexity | cuánto depende del azar/condiciones | L(ow), H(igh) |
| **PR** Privileges Required | privilegios previos del atacante | N(one), L(ow), H(igh) |
| **UI** User Interaction | ¿necesita que la víctima haga algo? | N(one), R(equired) |
| **S** Scope | ¿rompe el límite de seguridad del componente? | U(nchanged), C(hanged) |
| **C** / **I** / **A** | impacto en Confidencialidad / Integridad / Disponibilidad | N(one), L(ow), H(igh) |

Las tres últimas (C/I/A) son el **tríada de impacto**: dicen *qué se pierde*.

---

## 2. La fórmula de la puntuación base (y un ejemplo trabajado)

A partir del vector se deriva la **puntuación base** (0.0–10.0) y, de ahí, la
severidad cualitativa. Pesos oficiales (FIRST.org):

- AV: N=0.85, A=0.62, L=0.55, P=0.20 · AC: L=0.77, H=0.44 · UI: N=0.85, R=0.62
- C/I/A: H=0.56, L=0.22, N=0.00
- PR (depende de Scope): si S=U → N=0.85, L=0.62, H=0.27; si S=C → N=0.85, L=0.68, H=0.50

Pasos:

```
ISS            = 1 − [(1−C) · (1−I) · (1−A)]          (impacto "crudo")
Impact         = 6.42 · ISS                             (si Scope = U)
               = 7.52 · (ISS − 0.029) − 3.25 · (ISS − 0.02)^15   (si Scope = C)
Exploitability = 8.22 · AV · AC · PR · UI
BaseScore      = 0                                      (si Impact ≤ 0)
               = Roundup( min(Impact + Exploitability, 10) )       (si S = U)
               = Roundup( min(1.08 · (Impact + Exploitability), 10) )  (si S = C)
```

`Roundup(x)` redondea **hacia arriba** a un decimal (evitando errores de coma
flotante). Bandas de severidad: `0.0` NONE · `0.1–3.9` LOW · `4.0–6.9` MEDIUM ·
`7.0–8.9` HIGH · `9.0–10.0` CRITICAL.

**Ejemplo trabajado** con `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Scope U):

```
ISS  = 1 − (1−0.56)(1−0.56)(1−0.56) = 1 − 0.44^3 = 1 − 0.085184 = 0.914816
Impact = 6.42 · 0.914816 = 5.87312
Exploitability = 8.22 · 0.85 · 0.77 · 0.85 · 0.85 = 3.88704
suma = 5.87312 + 3.88704 = 9.76016  →  Roundup(9.76016) = 9.8  →  CRITICAL
```

El motor `cvss.py` reproduce **exactamente** los valores canónicos de referencia:
9.8, 7.5, 7.8, 6.1 y 3.1 (POODLE). Sobre los 6.000 vectores reales deriva la
severidad: **785 CRITICAL, 2.448 HIGH, 2.499 MEDIUM, 268 LOW**. Esto es una
validación de un motor determinista contra su especificación: la misma entrada da
siempre la misma salida, comprobable frente a la fórmula publicada.

---

## 3. Recuperar el impacto desde la prosa

Las descripciones de la NVD son **formularias**: "allows remote attackers to
**execute arbitrary code**", "cause a **denial of service**", "**obtain sensitive
information**". Esas frases mapean a la tríada de impacto. Definimos cuatro clases
mutuamente excluyentes a partir del vector (la verdad de terreno):

- **TOTAL** = C:H ∧ I:H ∧ A:H (compromiso completo: ejecución de código / escalada).
- **DOS** = solo disponibilidad (A afectada, C=N, I=N).
- **INFO** = solo confidencialidad (C afectada, I=N, A=N).
- **OTHER** = cualquier otro perfil mixto/parcial.

El predictor es un **mapa de frases curado**, igual en espíritu que el etiquetado
ATT&CK: lee la descripción (con `refang` reutilizado de `ioc.py`), y si encuentra
una frase conocida devuelve la clase y **la frase que la disparó** como evidencia.
Si no hay frase conocida, **se abstiene** (devuelve `None`) en vez de adivinar.

---

## 4. Las métricas y sus fórmulas

Para una clase (uno-contra-el-resto): `TP` aciertos, `FP` falsos positivos, `FN`
falsos negativos.

```
Precision = TP / (TP + FP)      ¿cuántas de las que predije así lo eran?
Recall    = TP / (TP + FN)      ¿cuántas de las reales capturé?
F1        = 2 · P · R / (P + R)  media armónica (castiga el desequilibrio)
Accuracy  = aciertos / total    (sobre todas las clases)
Macro-F1  = media de los F1 por clase (todas las clases pesan igual)
```

Dos referencias para saber si el resultado "vale":

- **Baseline mayoritario:** predecir siempre la clase más frecuente. Si no superas
  esto, tu motor no aporta información. Aquí la clase mayoritaria es TOTAL (0.376).
- **Covered-precision:** de las descripciones donde el mapa **sí dispara** una
  frase, ¿qué fracción acierta? Separa la calidad de las reglas de su cobertura.

**Ejemplo numérico trabajado** (conjunto held-out, 3.012 CVE). Clase DOS:
P=0.663, R=0.512 → `F1 = 2·0.663·0.512 / (0.663+0.512) = 0.67891 / 1.175 = 0.578`.
Macro-F1 = media de los cuatro F1:
`(0.579 + 0.578 + 0.498 + 0.000) / 4 = 1.655 / 4 = 0.414`.

Resultados en el **held-out** (3.012 CVE, partición sin fuga por hash del `cve_id`):

| Métrica | Valor | Referencia |
| ------- | ----- | ---------- |
| Accuracy | **0.487** | baseline mayoritario 0.376 |
| Macro-F1 | **0.414** | control barajado 0.173 |
| Covered-precision | **0.782** | (donde dispara una frase) |
| Coverage | 0.371 | (fracción donde dispara) |

| Clase | P | R | F1 | soporte |
| ----- | - | - | -- | ------- |
| TOTAL | 0.428 | 0.893 | 0.579 | 1133 |
| DOS | 0.663 | 0.512 | 0.578 | 516 |
| INFO | 0.764 | 0.369 | 0.498 | 517 |
| OTHER | 0.000 | 0.000 | 0.000 | 846 |

Lectura: supera el baseline por **11 puntos** de accuracy; donde dispara acierta el
**78%**; captura el **89%** de los compromisos totales (TOTAL recall). La precisión
baja de TOTAL (0.428) es un **efecto del respaldo mayoritario**: las filas donde el
motor se abstiene (incluidas las 846 de OTHER) se predicen como TOTAL, lo que suma
falsos positivos a esa clase. Por eso reportamos *covered-precision* aparte.

---

## 5. Sobreajuste e infraajuste (y cómo la brecha lo muestra)

Dos fallos clásicos de un componente aprendido:

- **Sobreajuste (overfitting):** memoriza el conjunto de desarrollo y no generaliza.
  Señal: error muy bajo en *train* pero alto en *test* → **brecha grande**
  (`accuracy_dev − accuracy_test` ≫ 0).
- **Infraajuste (underfitting):** el modelo es demasiado simple y no capta el patrón
  **ni** en train **ni** en test. Señal: error alto en ambos (sesgo alto).

threatscribe no entrena nada: el motor es **determinista** (un mapa de reglas). El
análogo de cada fallo:

- **Análogo de sobreajuste** = afinar las frases al conjunto de desarrollo. Lo
  detectamos con la **brecha dev–test** y con la validación cruzada. Aquí la brecha
  es **−0.036** (diminuta; el test incluso sale algo mejor que el dev 0.451), y la
  CV de 5 pliegues da **0.469 ± 0.018**. Varianza baja ⇒ las reglas **generalizan**,
  no están pegadas a un split.
- **Análogo de infraajuste / sesgo** = la clase **OTHER con recall 0**: el mapa no
  tiene frases para perfiles mixtos, así que no los capta. Es un sesgo **visible**
  (la cobertura 0.371 lo delata), no un error silencioso; se cierra añadiendo frases.

**Clasificación:** *bien ajustado* para las clases señaladas (TOTAL/DOS/INFO), con
un sesgo **conocido y acotado** en OTHER. La forma correcta de cerrarlo es ampliar
el mapa de frases, nunca "arreglar" la métrica degradando el motor.

---

## 6. El método: held-out + validación cruzada

- **Held-out (hold-out split):** partimos los 6.000 CVE en desarrollo (~2.988) y
  prueba (~3.012) **por hash del `cve_id`**. Así un CVE cae siempre del mismo lado,
  sin importar el orden ni la ejecución: la partición es **reproducible y sin fuga**.
  Medimos sobre el conjunto de prueba, que el desarrollo no vio.
- **Validación cruzada k-fold (k=5):** dividimos en 5 pliegues (otra vez por hash).
  Cada pliegue se evalúa por turnos; el **baseline mayoritario se calcula con los
  otros 4 pliegues** para no mirar las etiquetas del pliegue de prueba. Reportamos
  **media ± desviación** de accuracy y macro-F1. Mide **estabilidad**: si los
  números bailaran mucho entre pliegues, no podríamos confiar en una sola cifra.

---

## 7. El control de sanidad (scramble)

¿Y si el "acierto" fuera un artefacto del vocabulario y no de las frases? Para
descartarlo, **barajamos las palabras** de cada descripción (misma bolsa de
palabras, pero las frases multi-palabra como "execute arbitrary code" quedan
destruidas) y repetimos la evaluación.

- Real: accuracy **0.487**, macro-F1 **0.414**.
- Barajado: accuracy **0.387** (≈ baseline 0.376), macro-F1 **0.173**.

La señal **se desploma** hasta el baseline. Conclusión: lo que funciona son las
**frases**, no el mero vocabulario. Es el equivalente determinista al control de
**etiquetas barajadas** de un clasificador: si el truco es real, romper la entrada
debe colapsar la métrica. Aquí colapsa.

---

## 8. Los indicadores también concuerdan

Corriendo `ioc.extract` sobre las descripciones reales, el extractor recupera cada
identificador CVE incrustado con **precision y recall de 1.000** (176 descripciones
lo contienen) y extrae 1.131 indicadores en total **sin falsos positivos**: la
conducta exacta y reproducible que exige un feed de IOC.

---

## Para fijar la idea

- El vector CVSS es la verdad de terreno: estructura (AV/AC/PR/UI/S/C/I/A) +
  fórmula → puntuación y severidad. Nuestro motor la reproduce **exacta**.
- Recuperar el impacto desde la prosa supera el baseline en el held-out (0.487 vs
  0.376), acierta ~78% donde dispara y **generaliza** (brecha −0.036; CV 0.469 ±
  0.018).
- El **control barajado** colapsa la señal al baseline → la señal es real, está en
  las frases.
- Sobre/infraajuste: brecha pequeña ⇒ no "sobreajustado"; recall 0 en OTHER ⇒ sesgo
  visible que se cierra ampliando frases, nunca degradando el motor.
