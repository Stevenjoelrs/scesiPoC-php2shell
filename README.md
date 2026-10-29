# PHP2Shell — PoC local (CVE-2026-109618 / CVE-2026-109619)

Reproducción **solo de laboratorio** de la cadena *PHP2Shell*: un fallo en el
motor de PHP 8.4 que permite escapar de la corrupción de memoria controlada por
`memory_limit` hasta ejecución remota de código, sobre un Apache con `mod_php`
y un único worker prefork.

> **Aviso**: este repositorio ejecuta un contenedor deliberadamente vulnerable y
> contiene código de explotación. Úsalo únicamente contra las instancias locales
> que levanta el propio proyecto. No lo apuntes a sistemas de terceros.

## Estado

Fase 1 (esqueleto + laboratorio Docker) completa. El código Python del PoC, los
perfiles de offsets y la matriz vulnerable/parcheado están en construcción.

## Qué hay aquí

```
docker/
  compose.yml            vuln (8.4.26) + patched (8.4.27), solo 127.0.0.1
  php/lab-8m.ini         memory_limit=8M, upload progress, errores visibles
  apache/single-worker.conf  prefork con un único worker persistente
  www/index.php          página mínima ("OK")
  entrypoint.sh          arregla /out y delega en docker-php-entrypoint
poc/                     paquete Python del exploit (en construcción)
profiles/                perfiles de offsets por build (en construcción)
tests/                   tests stdlib unittest
scripts/                 utilidades (setup, offsets, matriz)
docs/                    laboratorio, arquitectura, etapas y blog
runtime/                 estado local ignorado por git (flag, /out)
results/                 resultados JSON/CSV ignorados por git
```

## Requisitos

- Docker Engine / Docker Desktop con el daemon arrancado.
- En Apple Silicon: emulación `linux/amd64` (Docker Desktop la incluye). El
  compose fija `platform: linux/amd64` para que los offsets de `libphp.so`
  coincidan con el laboratorio original.
- Python 3.9 o superior (el PoC evita sintaxis de 3.10+).

## Arranque rápido

```sh
make lab-up            # vulnerable en http://127.0.0.1:8088/
curl -fsS http://127.0.0.1:8088/   # -> OK

make lab-up-patched    # añade el control parcheado en :8089
make lab-ps
make lab-down
```

`make lab-up` crea `.env` a partir de `.env.example` y prepara:

- `runtime/f` — flag sintética (nunca la flag real de THM).
- `runtime/out` — destino de las pruebas (`/out` dentro del contenedor).

El contenedor vulnerable monta `runtime/f` en `/f` (solo lectura) y
`runtime/out` en `/out` (escritura para `www-data`), replicando la disposición
del laboratorio original.

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

## Hoja de ruta

- [x] Esqueleto del repositorio y laboratorio Docker.
- [ ] Núcleo Python: configuración, guardas de alcance, cliente HTTP.
- [ ] Perfiles de offsets (`bookworm`, `lab-8m`) y parser ELF de `libphp.so`.
- [ ] Fase de leak: direcciones de `zif_system`, `zval_ptr_dtor`, heap.
- [ ] Fase de RCE: cadenas de 14 bytes y stager.
- [ ] Matriz vulnerable/parcheado y detección.
- [ ] Documentación técnica y blog en español.

## Seguridad

- Los targets escuchan solo en loopback.
- El runner rechaza objetivos que no sean privados/locales salvo override
  explícito (se implementará en `poc/safety.py`).
- La flag pública del blog se redacta; el laboratorio usa una flag sintética.

## Referencias

- Aviso de PHP (2026-10-21): <https://www.php.net/archive/2026.php#2026-10-21-5>
- GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
- GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- Referencia de la cadena ASLR: <https://github.com/9bie/php2shell-bypass-aslr-exp>
