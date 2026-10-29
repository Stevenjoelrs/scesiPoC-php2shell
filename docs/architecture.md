# Arquitectura del PoC

## Principios

1. **Solo stdlib.** Python 3.9+, sin dependencias externas. El laboratorio debe
   poder reproducirse en un macOS limpio o en una VM Linux sin `pip install`.
2. **Fidelidad.** Imágenes oficiales, misma ini, mismo Apache, mismos puertos
   loopback. Los únicos cambios son el flag sintético y los paths del host.
3. **Trazabilidad.** Cada etapa registra lo que obtiene (cookie, base, offsets)
   y el resultado se puede guardar en JSON.
4. **Scope guard.** El runner rechaza targets públicos salvo override explícito
   y fija la IP resuelta para evitar DNS rebinding.

## Mapa de módulos

| Módulo | Responsabilidad |
| --- | --- |
| `poc/config.py` | dataclasses de target, exploit y laboratorio; parseo de `.env` |
| `poc/safety.py` | resolución DNS, clasificación de IPs y guarda de alcance |
| `poc/http.py` | cliente HTTP/1.1 mínimo con lectura concurrente y parser de respuestas |
| `poc/multipart.py` | constructor `multipart/form-data` con las formas exactas de la cadena |
| `poc/offsets.py` | parser ELF64 de `libphp.so` (`zif_system`, `zval_ptr_dtor`) y `docker cp` |
| `poc/profiles.py` | carga/validación de perfiles de calibración y fingerprint |
| `poc/exploit.py` | etapas 0–3, payloads y orquestación con reintentos |
| `poc/detect.py` | versión por banner y veredicto del probe de leak |
| `poc/lab.py` | estado de contenedores, healthcheck, `docker compose`, runtime |
| `poc/cli.py` | subcomandos `doctor`, `smoke`, `detect`, `offsets`, `leak`, `exploit`, `matrix` |

## Flujo

```
                 ┌──────────────┐
                 │    cli.py    │
                 └──────┬───────┘
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
   config.py        safety.py        lab.py
        │               │                │
        └───────┬───────┴────────┬───────┘
                ▼                ▼
           profiles.py       offsets.py
                │                │
                └───────┬────────┘
                        ▼
                   exploit.py ──► http.py ──► multipart.py
                        │
                        ▼
                    detect.py
```

`exploit.py` no sabe nada de Docker: recibe un `TargetConfig`, un `HttpClient`
y un `Profile` ya resueltos. Eso permite usarlo contra cualquier host
autorizado, no solo el laboratorio.

## Seguridad

### Scope guard

`poc/safety.py` resuelve el host una vez y devuelve una `Resolution` con la
lista de IPs. El cliente se conecta a `resolution.primary`, pero envía el
`Host` original. Así, la comprobación y la conexión usan la misma dirección.

- Loopback, privadas, link-local y rangos no globales: permitidos.
- Públicas: rechazadas salvo `--allow-public` o `--allow-host`.
- Multicast, `0.0.0.0` y direcciones inválidas: siempre rechazadas.

El compose publica solo en `127.0.0.1`. El guard es una segunda capa, no la
única.

### Datos y secretos

- La flag del reto nunca se versiona. El repo usa una flag sintética.
- `runtime/` y `results/*.json` están ignorados.
- El PoC no ejecuta comandos locales a partir de la respuesta del target: el
  comando se envía como argumento de `zif_system` y el proof se lee de un
  archivo local o de un `GET` explícito.

## Offsets

El binario `libphp.so` es un ELF64 little-endian. `poc/offsets.py`:

1. Copia `/usr/lib/apache2/modules/libphp.so` del contenedor con `docker cp`.
2. Localiza `PT_LOAD` y calcula el bias mínimo.
3. Recorre `.symtab`/`.dynsym` y su `.strtab`.
4. Devuelve `st_value - bias` para `zif_system` y `zval_ptr_dtor`.
5. Guarda `ZIF_OFFSET`, `DTOR_OFFSET`, el SHA-256 del binario y el contenedor.

En el laboratorio los offsets se extraen automáticamente del contenedor que
corresponde al puerto. Si el target es remoto, se usa `--offsets-file` o los
valores del perfil.

Valores observados:

| Imagen | `zif_system` | `zval_ptr_dtor` | SHA-256 (12) |
| --- | --- | --- | --- |
| 8.4.26 | `0x465370` | `0x65eb60` | `51663cf883b1` |
| 8.4.27 | `0x46ad70` | `0x66a620` | `5e2e2fcb7d1d` |

## Perfiles

Un perfil contiene las constantes que **no** se pueden derivar del ELF:

- `stage1_n`, `stage2_t`, `stage2_v`: número y forma de los campos de grooming.
- `stage3_pads`: longitudes de nombre/valor que colocan el fake reference.
- `stage3_carrier`: si se usa el carrier de 15 bytes o el `ref` directo.
- `stage3_cookie`: si se envía una cookie de sesión válida en la etapa 3.
- `htdata_offset`: offset del string de 167 bytes respecto del chunk base.

Los JSON de `profiles/` son la fuente de verdad. `load_profile()` valida los
rangos y calcula un SHA-256 canónico; el fingerprint se guarda en la matriz
para que un resultado sea atribuible a una configuración exacta.

`bookworm` es el perfil del laboratorio oficial. `lab` conserva la calibración
del build mínimo histórico y no se usa con las imágenes oficiales.

## Resultados

`ExploitResult` contiene:

```json
{
  "success": true,
  "chunk_base": "0x7ffffc400000",
  "libphp_base": "0x7ffffe013000",
  "htdata": "0x7ffffc4690d8",
  "zif": "0x7ffffe478370",
  "proof": "uid=33(www-data) ...",
  "stage": "rce",
  "stage1_cookie_len": 4096,
  "stage2_cookie_len": 16,
  "attempts": 3,
  "elapsed": 6.9,
  "error": ""
}
```

`matrix` escribe un JSON con el perfil, el fingerprint, las imágenes, los
offsets efectivos y el resultado de cada target. El veredicto
`PATCHED_CONTROL_OK` exige que el vulnerable tenga proof y que el parcheado no.

## Compatibilidad con Python 3.9

- No se usan uniones `X | Y` ni genéricos builtin (`list[...]`) en tiempo de
  ejecución.
- `from __future__ import annotations` se usa solo para comodidad de tipado.
- `dataclasses`, `ipaddress`, `socket`, `ssl`, `threading`, `gzip`, `json` y
  `unittest` son stdlib disponibles en 3.9.
- `make check` ejecuta `compileall` y la suite `unittest`.

## Tests

La suite cubre:

- parseo de `.env`, validación de URLs y límites del comando;
- clasificación de IPs y política de alcance;
- bytes exactos del multipart;
- parser HTTP (Content-Length, chunked, gzip, cookies);
- parser ELF con un binario sintético;
- perfiles, fingerprints y payloads fake;
- umbrales de detección por versión.

Los tests no requieren Docker. La validación end-to-end se hace con
`make lab-up-patched` + `make matrix`.
