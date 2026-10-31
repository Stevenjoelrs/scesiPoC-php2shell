# PHP2Shell — PoC local (CVE-2026-109618 / CVE-2026-109619)

Reproducción **solo de laboratorio** de la cadena *PHP2Shell*: una corrupción
de estado en el camino de *bailout* de PHP que, con `memory_limit` bajo y
sesiones con *upload progress*, permite filtrar el heap y la base de
`libphp.so` por `Set-Cookie`, escribir una referencia falsa y ejecutar
comandos vía `zif_system` sobre Apache `mod_php` con un worker prefork.

> **Aviso**: este repositorio ejecuta un contenedor deliberadamente vulnerable y
> contiene código de explotación. Úsalo únicamente contra las instancias locales
> que levanta el propio proyecto. No lo apuntes a sistemas de terceros.

## Estado

PoC completo y reproducible:

- laboratorio Docker con `php:8.4.26-apache` (vulnerable) y
  `php:8.4.27-apache` (control parcheado);
- cadena de tres etapas en Python 3.9, solo stdlib;
- extracción automática de offsets desde el `libphp.so` del contenedor;
- detección pasiva por banner y *probe* conductual de la etapa 1;
- matriz vulnerable/parcheado con veredicto y JSON reproducible;
- 72 tests unitarios sin Docker;
- documentación técnica y blog en español.

Resultado de la última matriz (`PATCHED_CONTROL_OK`):

| Target | PHP | Cookie etapa 1 | Leak | RCE |
| --- | --- | --- | --- | --- |
| `127.0.0.1:8088` | 8.4.26 | 4096 B | sí | sí (`uid=33(www-data)`) |
| `127.0.0.1:8089` | 8.4.27 | 32 B | no | no |

## Estructura

```
docker/
  compose.yml                vuln (8.4.26) + patched (8.4.27), solo 127.0.0.1
  php/lab-8m.ini             memory_limit=8M, upload progress, errores visibles
  apache/single-worker.conf  prefork con un único worker persistente
  www/index.php              página mínima ("OK")
  entrypoint.sh              arregla /out y delega en docker-php-entrypoint
poc/
  config.py                  dataclasses, .env y validación
  safety.py                  scope guard y clasificación de IPs
  http.py                    cliente HTTP/1.1 con lectura concurrente
  multipart.py               constructor multipart exacto
  offsets.py                 parser ELF64 de libphp.so + docker cp
  profiles.py                perfiles de calibración y fingerprint
  exploit.py                 etapas 0–3 y orquestación
  detect.py                  versión por banner y veredicto del probe
  lab.py                     estado de contenedores y docker compose
  cli.py                     subcomandos
profiles/                    bookworm.json (oficial), lab.json (histórico)
tests/                       72 tests stdlib unittest
docs/                        laboratorio, arquitectura, etapas, resultados, blog
runtime/                     flag sintética y proofs (ignorado por git)
results/                     matrices JSON (ignorado por git)
```

## Requisitos

- Docker Engine / Docker Desktop con el daemon arrancado y el plugin
  **Compose v2** (`docker compose`, no `docker-compose`).
- Python 3.9 o superior (el PoC evita sintaxis de 3.10+).
- El compose fija `platform: linux/amd64` para que los offsets y el layout de
  `libphp.so` coincidan con el binario x86-64 del laboratorio.

### Compatibilidad de host

| Host | Estado | Notas |
| --- | --- | --- |
| Linux x86_64 | nativo | Docker Engine + Compose v2; es el caso esperado |
| Linux arm64 | con emulación | requiere binfmt/QEMU para `linux/amd64` |
| macOS arm64 | con Docker Desktop | emulación integrada |
| macOS x86_64 | nativo | Docker Desktop |

El laboratorio se validó en macOS arm64 con Docker Desktop. No se ha ejecutado
en un host Linux real dentro de este repositorio, pero el diseño no depende de
macOS: usa Docker, Compose v2 y Python estándar. `make doctor` comprueba lo
básico antes de lanzar el exploit.

En Linux arm64, registra el emulador antes de arrancar el laboratorio:

```sh
docker run --privileged --rm tonistiigi/binfmt --install amd64
```

En Fedora/RHEL con SELinux enforcing, los bind mounts pueden necesitar la
etiqueta `:z`; en Ubuntu/Debian no hace falta. `make doctor` avisa de los casos
más comunes. Detalles en [`docs/lab.md`](docs/lab.md#linux).

## Arranque rápido

```sh
make lab-up-patched    # vulnerable :8088 + control :8089
make doctor            # Python, Docker, compose, contenedores, ini, /out
make exploit           # cadena completa; escribe /out/p1
make matrix            # vulnerable vs parcheado + JSON
```

Solo el target vulnerable:

```sh
make lab-up            # http://127.0.0.1:8088/
make lab-down
```

`make lab-up*` crea `.env` a partir de `.env.example`, prepara `runtime/f`
(flag sintética) y `runtime/out` (destino de los proofs). El contenedor monta
`runtime/f` en `/f` (ro) y `runtime/out` en `/out` (rw), replicando la
disposición del laboratorio original.

## Comandos

| Comando | Uso |
| --- | --- |
| `make doctor` | comprueba Docker, compose, contenedores, ini y `/out` |
| `make smoke` | `GET` al target (`URL=...` para cambiarlo) |
| `make leak` | etapas 1 y 2: heap y `libphp.so` |
| `make exploit` | cadena completa con `id>/out/p1` |
| `make exploit CMD='cat /f>/out/p1'` | lee la flag sintética (14 bytes) |
| `make detect` | fingerprint pasivo por `X-Powered-By` |
| `make matrix` | ejecuta vulnerable y parcheado, guarda JSON |
| `make check` | `compileall` + 72 tests |
| `make lab-reset` | limpia `runtime/out` |
| `make lab-down` | para y elimina los contenedores |

El CLI también se puede usar directamente:

```sh
python3 -m poc doctor
python3 -m poc detect -u http://127.0.0.1:8088/index.php
python3 -m poc detect --probe -u http://127.0.0.1:8088/index.php --json
python3 -m poc leak -u http://127.0.0.1:8088/index.php
python3 -m poc exploit -u http://127.0.0.1:8088/index.php -c 'cat /f>/out/p1'
python3 -m poc matrix --retries 3
```

`make detect` es pasivo. Para el *probe* conductual:

```sh
python3 -m poc detect --probe -u http://127.0.0.1:8088/index.php
```

## Resultados

Cadena completa contra 8.4.26:

```text
[*] stage 1: heap leak (attempt 1/3)
[+] chunk base = 0x7ffffc400000
[*] stage 2: libphp leak (attempt 1/3)
[+] libphp base = 0x7ffffe013000
[*] stage 3: HTDATA=0x7ffffc4690d8 ZIF=0x7ffffe478370
[+] RCE on stage 3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Flag sintética:

```sh
make exploit CMD='cat /f>/out/p1'
# PROOF: FLAG{php2shell_lab_synthetic_flag_redacted}
```

Control parcheado:

```text
[patched] [-] heap leak missed
[-] patched: BLOCKED at stage0 after 3 attempts (4.4s): HEAP_LEAK_FAILED
[=] verdict: PATCHED_CONTROL_OK
```

La cookie de la etapa 1 pasa de **4096 bytes** en 8.4.26 a **32 bytes** en
8.4.27. Los offsets del control se extraen de su propio `libphp.so`
(`zif=0x46ad70`, `dtor=0x66a620`), así que el fallo no se puede atribuir a
constantes del binario vulnerable. El control demuestra que el primitivo de
leak está bloqueado; no demuestra de forma independiente que la etapa 3 esté
bloqueada, porque la cadena no llega a ella.

Detalle completo en [`docs/results.md`](docs/results.md).

## Fidelidad con el laboratorio de THM

| Elemento | THM / referencia | Este repo |
| --- | --- | --- |
| Imagen vulnerable | `php:8.4.26-apache` | igual, imagen oficial |
| Imagen parcheada | — | `php:8.4.27-apache` |
| `memory_limit` | `8M` | igual |
| Errores | `display_errors=On`, `E_ALL` | igual |
| Upload progress | activo, `cleanup=On` | igual |
| Apache | prefork, 1 worker, `KeepAlive Off` | igual |
| Flag | `/f` | `/f` (sintética) |
| Salida | `/out` | `/out` |
| Puertos | remotos | solo `127.0.0.1` |

No hay build propio del target: se usan las imágenes oficiales para que la
única diferencia entre vulnerable y parcheado sea el nivel de PHP.

El healthcheck comprueba el PID de Apache, no HTTP, para no perturbar el único
worker entre peticiones de grooming.

## Configuración

Copia `.env.example` a `.env` (lo hace `make env`) y ajusta si hace falta:

| Variable | Por defecto | Uso |
| --- | --- | --- |
| `PLATFORM` | `linux/amd64` | plataforma de las imágenes |
| `VULN_IMAGE` | `php:8.4.26-apache` | target vulnerable |
| `PATCHED_IMAGE` | `php:8.4.27-apache` | control parcheado |
| `VULN_PORT` | `8088` | puerto local del vulnerable |
| `PATCHED_PORT` | `8089` | puerto local del parcheado |

Los puertos se publican siempre en `127.0.0.1`; no cambies el binding a
`0.0.0.0` en un equipo conectado a una red no confiable.

### Offsets y perfiles

`poc/offsets.py` copia `libphp.so` del contenedor y parsea `.symtab`/`.dynsym`
para obtener `zif_system` y `zval_ptr_dtor`. El runner prefiere el contenedor
en ejecución antes que una caché compartida, porque vulnerable y parcheado
tienen offsets distintos.

| Imagen | `zif_system` | `zval_ptr_dtor` |
| --- | --- | --- |
| 8.4.26 | `0x465370` | `0x65eb60` |
| 8.4.27 | `0x46ad70` | `0x66a620` |

`profiles/bookworm.json` contiene las constantes de grooming que no se pueden
derivar del ELF (`stage1_n=841`, `stage2_t=406`, `stage2_v=16`, pads de la
etapa 3 y `htdata_offset=0x690d8`). `profiles/lab.json` conserva la calibración
histórica del build mínimo y no se usa con las imágenes oficiales.

## Cómo funciona

1. **Etapa 0** — aborta el worker con un POST que supera `memory_limit`; prefork
   crea un hijo limpio.
2. **Etapa 1** — un `zend_string` falso hace que la sesión serialice 4096 bytes
   de punteros del heap en `Set-Cookie`; la moda alineada a 2 MB es el chunk
   base de Zend MM.
3. **Etapa 2** — una página falsa de `HashTable` filtra `zval_ptr_dtor` en una
   cookie de 16 bytes; restando el offset ELF se obtiene la base de
   `libphp.so`.
4. **Etapa 3** — un carrier de 15 bytes escribe una referencia falsa sobre
   `PS(http_session_vars)`; un `HashTable` falso de 167 bytes pone
   `zif_system` en `pDestructor` y un `execute_data` con un argumento de tipo
   string. Al destruir la sesión, el motor ejecuta el comando.

El comando máximo es de **14 bytes** (`cat /f>/out/p1`). Comandos más largos
requieren un stager `sh</out/c`, que este PoC no implementa.

Explicación detallada: [`docs/stages.md`](docs/stages.md).

## Tests

```sh
make check
```

Cubre configuración y `.env`, scope guard, multipart byte a byte, parser HTTP
(Content-Length, chunked, gzip, cookies), parser ELF con un binario sintético,
perfiles y fingerprints, payloads falsos y umbrales de detección. No requiere
Docker.

## Seguridad

- Los targets escuchan solo en loopback.
- `poc/safety.py` resuelve el host una vez y conecta a la IP validada, enviando
  el `Host` original: no hay ventana de DNS rebinding.
- Se rechazan targets públicos salvo `--allow-public` o `--allow-host`.
- Multicast, `0.0.0.0` y direcciones inválidas se rechazan siempre.
- La flag del reto original nunca se usa ni se versiona; el laboratorio emplea
  `FLAG{php2shell_lab_synthetic_flag_redacted}`.
- `runtime/`, `results/*.json`, `refs/` y `.env` están ignorados por git.

## Limitaciones

- Las constantes de grooming son específicas de `php:8.4.26-apache`; otra
  imagen o arquitectura requiere recalibrar.
- La emulación `linux/amd64` en Apple Silicon cambia tiempos y direcciones,
  pero no la lógica de la cadena.
- El control parcheado se detiene en la etapa 1; no valida de forma aislada la
  etapa 3.
- `memory_limit=8M` y `display_errors=On` forman parte del entorno del reto; en
  producción la cadena de referencia no aplica tal cual.

## Documentación

- [`docs/lab.md`](docs/lab.md) — laboratorio Docker, paridad, permisos, diagnóstico.
- [`docs/architecture.md`](docs/architecture.md) — módulos, seguridad, offsets y perfiles.
- [`docs/stages.md`](docs/stages.md) — cadena etapa por etapa y layout del payload.
- [`docs/results.md`](docs/results.md) — evidencia capturada y JSON de la matriz.
- [`docs/blog.md`](docs/blog.md) — artículo completo en español.

## Referencias

- PHP 8 ChangeLog, 8.4.27 (22 oct 2026):
  <https://www.php.net/ChangeLog-8.php#8.4.27>
- Aviso de seguridad de PHP (octubre 2026):
  <https://www.php.net/archive/2026.php#2026-10-21-5>
- `GHSA-w8hw-w9fx-j79w` → CVE-2026-109618
- `GHSA-6wmf-4rv5-p3rp` → CVE-2026-109619
- Investigación y cadena de referencia de 9bie:
  <https://github.com/9bie/php2shell-bypass-aslr-exp>
- Imágenes oficiales de PHP para Docker:
  <https://github.com/docker-library/php>

## Créditos

- Investigación original y cadena ASLR: **9bie**
  ([`php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp)).
- Port a Python 3.9, laboratorio Docker, instrumentación, detección y
  documentación: este repositorio.

El código se publica con fines educativos y de defensa. Úsalo solo en sistemas
que controles o para los que tengas autorización explícita.
