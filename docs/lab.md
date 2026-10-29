# Laboratorio Docker

Este laboratorio reproduce, en local y solo sobre `127.0.0.1`, el entorno del
reto *PHP2Shell*: PHP 8.4.26 con `mod_php`, Apache prefork, `memory_limit=8M`,
errores visibles y un único worker. El objetivo es ejecutar la cadena completa
(leak de heap → leak de `libphp.so` → RCE) y compararla con el mismo entorno
sobre PHP 8.4.27.

> El contenedor vulnerable es deliberadamente inseguro. No publiques sus
> puertos fuera de loopback ni lo ejecutes en una máquina compartida sin
> aislamiento.

## Topología

```
host 127.0.0.1:8088 ──► php2shell-vuln    php:8.4.26-apache
host 127.0.0.1:8089 ──► php2shell-patched php:8.4.27-apache
                              │
                              ├─ /var/www/html      docker/www (ro)
                              ├─ /f                 runtime/f (ro)
                              └─ /out               runtime/out (rw)
```

Ambos servicios comparten exactamente la misma configuración de PHP y Apache.
La única variable es el nivel de parche de PHP.

## Imágenes

| Servicio | Imagen | Rol |
| --- | --- | --- |
| `vuln` | `php:8.4.26-apache` | vulnerable a CVE-2026-109618 / CVE-2026-109619 |
| `patched` | `php:8.4.27-apache` | control; incluye el fix del 2026-10-22 |

No hay build propio del target. Se usan las imágenes oficiales de
`docker-library/php` para conservar la fidelidad con el laboratorio original:
Debian bookworm, Apache 2.4.69 y `libphp.so` en
`/usr/lib/apache2/modules/libphp.so`.

El compose fija `platform: linux/amd64`. En Apple Silicon esto implica
emulación; es necesario para que los offsets y el layout de `libphp.so`
coincidan con el binario x86-64 del laboratorio.

## Configuración

`docker/php/lab-8m.ini` replica los ajustes del laboratorio de referencia:

```ini
display_errors = On
display_startup_errors = On
error_reporting = E_ALL

memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 64M

session.save_path = "/tmp"
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
```

`memory_limit=8M` es la pieza central: el campo `big` de 12 MB fuerza el camino
de OOM/bailout mientras el buffer de *upload progress* sigue vivo. Sin ese
límite, la cadena de referencia no aplica.

`docker/apache/single-worker.conf` fija un solo worker prefork:

```apache
KeepAlive Off

<IfModule mpm_prefork_module>
    StartServers           1
    MinSpareServers        1
    MaxSpareServers        1
    MaxRequestWorkers      1
    ServerLimit            1
    MaxConnectionsPerChild 0
</IfModule>
```

Con un worker persistente, el heap que se grooma en una petición sigue siendo
válido en la siguiente. El exploit rota el worker a propósito entre etapas
(stage 0) para partir siempre de un proceso limpio.

## Montajes

| Host | Contenedor | Modo | Uso |
| --- | --- | --- | --- |
| `docker/www` | `/var/www/html` | ro | `index.php` mínimo |
| `runtime/f` | `/f` | ro | flag sintética |
| `runtime/out` | `/out` | rw | pruebas del target vulnerable |
| `runtime/patched/out` | `/out` | rw | pruebas del control parcheado |
| `docker/entrypoint.sh` | `/usr/local/bin/php2shell-entrypoint` | ro | wrapper de arranque |

`make runtime` crea los directorios y la flag sintética. La flag real del reto
**no** se usa ni se versiona; el contenido por defecto es
`FLAG{php2shell_lab_synthetic_flag_redacted}`.

### Permisos en Docker Desktop

El entrypoint intenta `chown www-data:www-data /out`, pero VirtioFS (Docker
Desktop en macOS) ignora los cambios de propietario en bind mounts. Por eso el
Makefile deja `runtime/out` y `runtime/patched/out` en modo `0777`. En Linux el
`chown` suele bastar, pero el `0777` no estorba en un laboratorio local.

Si `/out` no es escribible, la etapa 3 puede ejecutar el comando pero el proof
no aparecerá en el host.

## Healthcheck

El healthcheck **no** hace HTTP:

```yaml
test: ["CMD-SHELL", "test -s /var/run/apache2/apache2.pid"]
```

Una petición HTTP periódica caería en el único worker y podría alterar el heap
entre las dos peticiones de una misma etapa. El chequeo por PID evita ese
efecto secundario. `make lab-smoke` sí hace una petición HTTP, pero solo cuando
tú lo pides.

## Arranque

```sh
make lab-up            # solo vulnerable
make lab-up-patched    # vulnerable + control
make lab-ps
make doctor
```

El primer arranque descarga las imágenes. En Apple Silicon la emulación puede
tardar unos segundos más.

## Comandos útiles

```sh
make smoke             # GET /
make leak              # stages 1 y 2
make exploit           # cadena completa; escribe /out/p1
make exploit CMD='cat /f>/out/p1'   # lee la flag sintética
make detect            # versión de PHP por cabecera
python3 -m poc detect --probe -u http://127.0.0.1:8088/index.php  # probe etapa 1
make matrix            # vulnerable vs parcheado
make lab-reset         # limpia /out
make lab-down
```

## Diagnóstico

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| `docker daemon unavailable` | Docker Desktop parado | arráncalo y repite |
| `no matching manifest` | plataforma distinta | deja `PLATFORM=linux/amd64` |
| `bind: address already in use` | puerto ocupado | cambia `VULN_PORT`/`PATCHED_PORT` en `.env` |
| `/out` no escribible | VirtioFS/permisos | `make runtime` (aplica `0777`) |
| etapa 1 falla siempre | worker ocupado o config distinta | `make lab-reset`, revisa `lab-8m.ini`, rota el worker |
| contenedor en restart | entrypoint sin comando | verifica `command: ["apache2-foreground"]` en el compose |

## Limpieza

```sh
make lab-down
```

`runtime/` y `results/*.json` están ignorados por git. Los contenedores no
guardan estado relevante: las sesiones viven en `/tmp` dentro del contenedor y
se pierden al recrearlo.
