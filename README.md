# BugFinder

Strumento euristico per identificare potenziali bug nel codice e tracce di codice generato da AI.

## Installazione

Assicurati di avere Python 3 installato e nel PATH.

```powershell
python --version
```

Se non è installato, scaricalo da https://www.python.org/ o dal Microsoft Store.

## Utilizzo base

Analizza l'intera directory corrente:

```powershell
python bugfinder.py .
```

Genera un report HTML:

```powershell
python bugfinder.py . -f html
```

Mostra solo bug di severità **alta** o **critical**:

```powershell
python bugfinder.py . --min-severity high
```

## Cartella di test

È inclusa una cartella `tests` con alcuni file di esempio pensati per far scattare diversi pattern:

- `tests/sample_c.c`
- `tests/sample_py.py`
- `tests/sample_js.js`

Per analizzare solo i test:

```powershell
python bugfinder.py tests
```

Ricorda: i risultati sono **euristici**. Ogni segnalazione va verificata manualmente.
