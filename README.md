# EML Inspector

Analizador forense de correos `.eml` y `.msg` que funciona entero en el navegador, sin dependencias ni paso de compilación. El contenido de los correos nunca sale del equipo. Las comprobaciones en línea (DNS y WHOIS) se ejecutan por defecto y sólo envían dominios, IPs y selectores DKIM; se pueden desactivar. Opcionalmente, con una clave de API, se consultan los enlaces en Google Safe Browsing enviando sólo prefijos de hash.

## Uso

- **Windows:** doble clic en `iniciar.bat`. Levanta un servidor en `http://localhost:8000` y abre el navegador.
- **Manual:** `python -m http.server 8000` en esta carpeta y abre `http://localhost:8000`.
- También puedes abrir `index.html` directamente. El análisis funciona igual, pero la IA local y el botón de ejemplos necesitan `http://localhost`.

Para cargar correos: arrástralos a la ventana, usa **Abrir correo** o pega el código fuente con `Ctrl+V`.

### Cómo exportar el correo para que el análisis sea completo

| Origen | Cómo guardarlo | Resultado |
|---|---|---|
| Outlook en la web / nuevo Outlook | ··· › **Descargar** | `.eml` original: análisis completo, incluida la verificación DKIM |
| Gmail | ⋮ › **Descargar mensaje** | `.eml` original: análisis completo |
| Outlook de escritorio | **Arrastrar el correo al escritorio** | `.msg` con las cabeceras originales: autenticación y ruta completas. La firma DKIM no se puede volver a verificar, porque Outlook guarda el cuerpo en su propio formato |
| Outlook de escritorio | Archivo › Guardar como › `.eml` | Outlook **reconstruye** el mensaje y elimina `Authentication-Results` y `DKIM-Signature`. La herramienta lo detecta y usa en su lugar el veredicto que Microsoft deja en `X-Microsoft-Antispam-Mailbox-Delivery` (`auth`, `dest`) y el SCL |

En `samples/` hay cuatro ejemplos: un phishing bancario, una newsletter legítima, una factura con adjuntos maliciosos y una multa falsa con un código QR.

## Qué analiza

| Pestaña | Contenido |
|---|---|
| Resumen | Conclusión en lenguaje llano (veredicto, motivos principales y qué hacer), resumen por áreas, tarjeta de **Reputación** con el resultado de cada fuente en línea (Google Safe Browsing, Cloudflare 1.1.1.2, listas negras de dominios e IPs, antigüedad WHOIS, dominios inexistentes o suspendidos), también cuando no encuentran nada, hallazgos agrupados por gravedad, con los informativos y los que restan riesgo plegados (al pulsar uno se abre su detalle), panel de IA y datos clave |
| Contenido | HTML en un iframe aislado, sin scripts, con los enlaces desactivados (al pasar el ratón se ve el destino real) y las imágenes remotas bloqueadas. Vista de texto y traducción |
| Origen › Autenticación | SPF, DKIM, DMARC, ARC, compauth, alineación de dominios, **verificación criptográfica DKIM** y veredictos antispam de los servidores (Microsoft 365 SCL/SFV/CAT, SpamAssassin, Rspamd) |
| Origen › Ruta de entrega | Saltos `Received` en orden cronológico: TLS, retrasos y el salto en que el correo entró en tu proveedor. La **IP de origen** es la que anotó tu proveedor al recibirlo (fiable); la del primer salto se muestra aparte como «declarada», porque el remitente puede inventar esos `Received` |
| Enlaces | Texto visible frente a destino real, IPs, punycode, acortadores, TLD de riesgo, dominios que imitan marcas, formularios y enlaces sacados de códigos QR. Con las comprobaciones en línea, cada enlace muestra también si su dominio no existe, es reciente, está suspendido o figura en listas negras. No se visita ningún enlace: de los redireccionadores no se conoce el destino final |
| Adjuntos | SHA-256 y SHA-1, tipo real por *magic bytes*, doble extensión, macros, ZIP cifrado, con ejecutables o manipulado (el contenido se lee del directorio central), PDF con JavaScript y **códigos QR** en imágenes. Los `.eml` adjuntos se pueden abrir y analizar |
| DNS y WHOIS | Antigüedad y registrador de los dominios, MX/SPF/DMARC del remitente, titular y DNS inverso de la IP de origen, y listas negras |
| IOCs | IPs, dominios, correos, URLs y hashes, exportables a CSV o JSON. Con las comprobaciones en línea, cada IP, dominio y URL muestra su reputación: las alertas (listas negras, dominio inexistente o reciente, Safe Browsing; cada URL hereda además las de su dominio o IP), «sin coincidencias» si se consultó sin resultados (en gris: no prueba que sea seguro) o nada si no se consultó. La misma información va en la columna `reputacion` del CSV. Los valores que empiezan por `=`, `+`, `-` o `@` llevan delante `'` para que Excel no los ejecute como fórmula. Opción de *defang* (`evil.com` → `evil[.]com`) al copiar y en el CSV |
| Avanzado | Cabeceras decodificadas (RFC 2047) con filtro, árbol MIME y código fuente del mensaje |

### Atajos de teclado

| Tecla | Acción |
|---|---|
| `O` | Abrir ficheros |
| `Ctrl`+`V` | Pegar el código fuente de un correo |
| `J` / `K` | Correo siguiente / anterior |
| `/` | Buscar en la lista de correos |
| `1` … `8` | Ir a una pestaña |
| `←` `→` | Cambiar de pestaña con la barra enfocada |
| `E` | Menú de exportación |
| `Supr` | Quitar el correo seleccionado en la lista |
| `?` | Ver todos los atajos |

### Qué cabeceras se creen

Cualquiera puede escribir cualquier cabecera al enviar un correo, incluidas `Authentication-Results` y `Received`. Sólo las que añade tu proveedor son fiables:

- **Authentication-Results:** sólo cuenta el más alto de un servidor que aparece en la ruta (algún `Received` «by» suyo; Microsoft, Google y Apple se reconocen aunque su authserv-id sea de otro dominio). Los demás se muestran marcados como ignorados, y si uno lo escribió un servidor ajeno a la ruta, se avisa (+10). Límite: si tu proveedor no añade ninguno y el atacante adivina su nombre, no se puede distinguir.
- **X-Microsoft-Antispam-Mailbox-Delivery** (`auth:1`): sólo si el correo lo entregó Microsoft y DMARC no falla.
- **Correos adjuntos** («Analizar como correo»): no los recibió tu proveedor, así que su autenticación no resta riesgo y se muestra un aviso.

Otras comprobaciones locales:

- **Dominios parecidos a marcas:** homóglifos (`paypa1`, `rnicrosoft`), typosquatting (`microsfot`), marca combinada con otras palabras (`caixabank-seguridad.com`), marca en un subdominio (`paypal.com.login.xyz`) o marca con un TLD no oficial.
- **Dominios inválidos o aleatorios** en From, Return-Path y Reply-To (`-----mail.BWUAwMUztrzld.com`).
- **Falsas respuestas:** asunto «RE:»/«RV:» sin `In-Reply-To` ni `References` (y con `Thread-Index` de conversación nueva), típico del fraude de facturas.
- **Enlaces personalizados:** tu dirección dentro de la URL, en base64 o tras `#` (kits que rellenan el login falso), sin contar los enlaces de baja.
- **Adjuntos HTML/SVG:** destino de los formularios, peticiones de contraseña, código ofuscado (`atob`, `eval`, `unescape`…), exfiltración (bots de Telegram, webhooks de Discord, `fetch`) y URLs ocultas en `atob("…")`, que pasan a la lista de enlaces.
- **Quishing:** decodifica los QR de las imágenes adjuntas o incrustadas y analiza la URL como un enlace más.
- **Redireccionadores de seguimiento:** los enlaces de marketing que pasan por la plataforma de envío (Mailchimp, SendGrid, SparkPost, etc.) no se marcan como engañosos.
- **Ocultar mi correo de Apple:** los correos que llegan a un alias de `privaterelay.appleid.com` traen el From reescrito (`hello_at_hinge_co_…@privaterelay.appleid.com`) y el SPF/DKIM/DMARC de Apple, que sólo prueban que el correo pasó por Apple. La herramienta recupera el remitente real (`hello@hinge.co`), le aplica las comprobaciones de remitente (marcas, dominio gratuito, Reply-To, WHOIS…) y usa como autenticación la que Apple comprobó al recibirlo (`Authentication-Results` de `dkim-verifier.icloud.com` y `spf.icloud.com`). Sólo se trata como reenvío si el DMARC de Apple no falla; si falla, es una falsificación del formato. Las firmas DKIM originales que el reenvío invalida se muestran como informativas.

### Puntuación

Cada hallazgo suma según su gravedad (alto +25, medio +10, bajo +4). Las **evidencias a favor** restan:

| Evidencia | Puntos |
|---|---|
| DMARC correcto | −10 |
| DKIM correcto y alineado | −5 |
| Microsoft autenticó al remitente (`auth:1`), si no hay DMARC | −10 |
| Apple autenticó al remitente real (DKIM o SPF alineados), si lo reenvía «Ocultar mi correo» | −10 |
| DKIM verificado aquí y alineado, si el servidor no lo había validado | −5 |
| Dominio del remitente con más de 2 / 10 años, **sólo si el remitente está autenticado** | −5 / −10 |

Las evidencias a favor restan como máximo 30 puntos, y solo 10 si hay alguna alerta grave, porque una cuenta legítima puede estar comprometida. Un enlace en las listas de Google Safe Browsing suma 60, de modo que por sí solo deja el correo en riesgo alto. En el Resumen se ve el desglose y los puntos de cada hallazgo.

**La autenticación no prueba que el remitente sea de fiar.** SPF, DKIM y DMARC sólo demuestran que el correo viene del dominio del From: un atacante que registra `caixabank-seguridad.com` y lo configura bien los pasa todos. Por eso esas evidencias (y la antigüedad del dominio) **no restan nada** si el propio dominio del remitente es sospechoso:

- imita una marca (homóglifo, typosquatting, marca combinada, en un subdominio o con otro TLD);
- el nombre visible dice ser una marca y el dominio no es suyo, o contiene otra dirección;
- es inválido o aleatorio;
- es de un proveedor gratuito (gmail.com, outlook.com…), donde cualquiera puede abrir una cuenta;
- en línea: se registró hace menos de 180 días, está suspendido o figura en listas negras.

Si además el correo está autenticado y se hace pasar por otro, se añade **«Remitente autenticado que se hace pasar por otro»** (+10): es la técnica habitual para esquivar los filtros y no debe puntuar mejor que una falsificación del From, que al menos fallaría DMARC. En la interfaz, los puntos anulados se muestran tachados.

Desde la cabecera del correo se exporta un informe en Markdown o JSON que incluye los resultados en línea.

## Comprobaciones en línea

Se ejecutan **automáticamente al abrir cada correo**. Se pueden desactivar con la casilla «Ejecutar al abrir cada correo», en **Ajustes** de la pestaña *DNS y WHOIS*, y lanzar a mano con el botón **Comprobaciones en línea** de la cabecera del correo.

| Qué | Cómo | Qué se envía |
|---|---|---|
| Verificación DKIM | Obtiene la clave pública por DNS y comprueba la firma con WebCrypto. Admite RSA-SHA256, RSA-SHA1 y Ed25519, canonicalización simple y relaxed, `l=`, `t=y` y claves revocadas. Las firmas que tu proveedor ya comprobó no se verifican solas (botón «Verificar todas las firmas») | `selector._domainkey.dominio` |
| DNS | Existencia del dominio, MX, SPF, DMARC y PTR, mediante DNS-over-HTTPS (Cloudflare o Google, a elegir; a Google se le pide que no reenvíe tu subred, ECS) | Dominios e IP de origen |
| WHOIS | RDAP, el sucesor en JSON de WHOIS: fecha de registro, caducidad, registrador y estado. El servidor de cada TLD se localiza con el bootstrap de IANA | Dominio registrable |
| IP de origen | RDAP del RIR correspondiente: organización, país, rango y contacto de abuso | IP |
| Listas negras | SpamCop, PSBL, DroneBL, Barracuda y URIBL | IP y dominios |
| Cloudflare 1.1.1.2 | Consulta A de cada dominio al resolvedor con filtro de malware de Cloudflare (`security.cloudflare-dns.com`). Si responde `0.0.0.0` con el error extendido `EDE(16)`, Cloudflare lo clasifica como malicioso y se trata como una lista negra más | Dominios (a Cloudflare, aunque el resolvedor elegido sea Google) |
| Google Safe Browsing (opcional) | API v5 `hashes.search`: cada enlace (incluidos los de los códigos QR y la URL que lleve dentro un redireccionador) y los dominios del From, Return-Path y Reply-To se canonicalizan y se convierte en local en hasta 30 expresiones «host/ruta»; se envían los 4 primeros bytes de su SHA-256 y las coincidencias se confirman aquí con el hash completo | Prefijos de hash de 4 bytes, que comparten miles de URLs. Nunca la URL |

De los enlaces sólo se consulta el **dominio registrable**, nunca la URL ni el subdominio, porque los subdominios únicos por destinatario delatarían que se ha abierto el correo. El dominio registrable se calcula con un extracto de la Public Suffix List: en plataformas de alojamiento compartido (`github.io`, `pages.dev`, `web.app`…) cada subdominio es de un cliente distinto, así que `evil.github.io` se trata como dominio propio y no se consulta su WHOIS, que sería el de la plataforma. Safe Browsing tampoco recibe URLs, sólo prefijos de hash.

Cada consulta DNS llega al servidor DNS del dominio consultado, que puede ser del remitente: una consulta horas después de la entrega le indica que alguien analiza el correo y, si el nombre es único por destinatario, quién. Para reducirlo:

- Si el From, Return-Path, Reply-To o `d=` de DKIM incluyen tu dirección (en claro o en base64), sólo se consulta su dominio registrable, y se indica en su tarjeta.
- Las firmas DKIM que tu proveedor ya comprobó, o cuyo selector incluye tu dirección, no se verifican automáticamente: pedir su clave llegaría al firmante (un selector puede ser único para cada víctima). Verificarlas sirve sobre todo para detectar un `.eml` modificado al exportarlo.
- El DNS inverso sólo se consulta para la IP de origen, que ya consultó tu proveedor; no para la del primer salto ni las de los enlaces, que elige el remitente.
- Las consultas a Google llevan `edns_client_subnet=0.0.0.0/0`: sin él, Google reenvía la subred de tu IP a los servidores autoritativos.

Lo que no se puede evitar sin renunciar a la comprobación es que el dueño de un dominio vea que se consulta de nuevo.

### Google Safe Browsing

Necesita una clave de API propia: en [Google Cloud](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) crea un proyecto, activa la **Safe Browsing API** y crea una clave. Conviene restringirla a esa API y, en «Restricciones de aplicaciones › Sitios web», a `http://localhost:8000/*` (la herramienta envía sólo el origen de la página como referer). La API responde en protobuf, que se decodifica en el navegador. Hay dos sitios donde ponerla:

- En `config.js`, en la raíz del proyecto: `safeBrowsingKey: 'tu-clave'`. Vale para cualquier navegador que abra la herramienta desde esta carpeta. Tras editarlo, recarga con `Ctrl`+`F5`. No compartas ese fichero con la clave puesta.
- En «Clave de Safe Browsing», en **Ajustes** de la pestaña *DNS y WHOIS*. Se guarda sólo en el `localStorage` de ese navegador y de esa dirección (`localhost:8000` y `127.0.0.1:8000` cuentan como distintas). Si tiene algo, se usa en lugar de la de `config.js`; si está vacío, el campo indica «usando config.js».

Sin clave no se consulta, salvo en la versión publicada (ver *Publicación*).


- Detecta URLs y dominios que Google ya tiene catalogados como phishing, malware, software no deseado o aplicaciones dañinas. Un dominio del remitente en las listas suma 60 puntos, igual que un enlace, y anula las evidencias a favor si es el del From.
- Al abrir un correo, las comprobaciones en línea esperan a que se lean los códigos QR, para consultar también sus enlaces. Si se lanzaron a mano antes, se repiten al aparecer enlaces nuevos. Que un enlace no figure no garantiza que sea seguro: las campañas recién lanzadas tardan en entrar en las listas.
- La Safe Browsing API es gratuita **sólo para uso no comercial**. Para uso comercial Google ofrece Web Risk.
- Como exigen sus condiciones, las alertas llevan el texto «Aviso proporcionado por Google», con enlace al aviso de Safe Browsing, y el aviso de que puede haber falsos positivos y negativos.

Notas:

- Spamhaus no se consulta: rechaza los resolvedores DNS públicos (a Google le contesta NXDOMAIN para todo) y sólo funciona con una clave DQS.
- Antes de dar una lista por limpia se consulta su punto de prueba (`127.0.0.2`, `test.uribl.com`) con el mismo resolvedor. Si no sale listado, la lista se muestra como «no consultable» en lugar de dar un falso «limpio». Es lo que pasa con URIBL si se usa Google.
- 1.1.1.2 sólo se usa como lista negra, nunca para el análisis: a los dominios que bloquea les niega también los registros TXT y MX, así que con él no se podrían verificar SPF, DMARC ni DKIM justo en los correos maliciosos. Como el resto de listas, en los enlaces sólo se consulta el dominio registrable: un bloqueo que Cloudflare aplique sólo a un subdominio del enlace no se detecta. En el remitente, Return-Path y Reply-To se consulta el nombre completo.
- Se pregunta a la vez a las dos IPs del servicio (`1.1.1.2` y `1.0.0.2`) y vale la primera respuesta: en algunas redes una de las dos no es alcanzable.
- Algunos registros, como `.es` o `.io`, no publican RDAP, así que no hay WHOIS consultable desde el navegador. Para esos se ofrece un enlace externo.
- Una firma DKIM que el servidor receptor dio por buena puede fallar aquí por dos motivos: el `.eml` se alteró al exportarlo o reenviarlo, o el remitente ya rotó la clave. Si el servidor dijo `pass`, ese fallo se trata como aviso leve.

## IA local (Gemini Nano)

Si el navegador expone las [APIs de IA integradas](https://developer.chrome.com/docs/ai/built-in), la herramienta las usa para lo siguiente:

- **Prompt API:** da un veredicto estructurado (legítimo, phishing, fraude, malware…) con confianza, razones y acción recomendada, combinando el texto con todos los hallazgos, incluidos los de las comprobaciones en línea. El veredicto se pide **una sola vez por correo**. También hay un chat para preguntar sobre el correo.
- **Summarizer API:** resume el mensaje en español.
- **Language Detector y Translator API:** detectan el idioma y traducen el cuerpo al español.

**Límites de tiempo** (en `AI.LIMITS`, dentro de `js/ai.js`):

| Operación | Límite |
|---|---|
| Veredicto | 120 s hasta obtener la respuesta, 150 s en total |
| Resumen y chat | 60 s hasta el primer fragmento, 30 s máximo entre fragmentos, 180 s en total |
| Descarga del modelo | No se corta mientras avance; se cancela si pasa 90 s sin progreso |

Cada operación tiene botón de **Cancelar** y un contador de tiempo. Al cortarse, se libera la sesión del modelo y se puede reintentar.

El modelo corre en el dispositivo: Gemini Nano en Chrome o Phi-4-mini en Edge. **Requisitos:** Chrome 138 o superior en escritorio, unos 22 GB libres y una GPU con más de 4 GB de VRAM (o 16 GB de RAM y 4 núcleos). Si la Prompt API no aparece, activa `chrome://flags/#prompt-api-for-gemini-nano` y `#optimization-guide-on-device-model`. El estado del modelo se consulta en `chrome://on-device-internals`.

## Publicación

La web se publica en `https://eml.alvaropiquerastrenado.com` (hosting compartido de Hostinger) con el workflow `.github/workflows/deploy.yml`, que en cada push a `main` sube los ficheros por FTP. Necesita estos secrets en el repositorio: `GOOGLE_SAFE_BROWSER` (clave de Safe Browsing), `FTP_SERVER`, `FTP_USERNAME` y `FTP_PASSWORD` (una cuenta FTP cuyo directorio sea la carpeta del subdominio). Si la cuenta FTP apunta a otra carpeta, la variable `FTP_SERVER_DIR` indica la de destino.

El despliegue escribe un `config.js` sin clave que apunta a `api/safebrowsing.php`, y guarda la clave en `api/sb-key.php`. Ese proxy PHP recibe sólo prefijos de hash, añade la clave en el servidor y devuelve la respuesta de Google, así que la clave nunca llega al navegador. Sólo acepta peticiones de la propia web, como mucho 400 prefijos por petición y 120 peticiones por IP cada 10 minutos. Como la llamada a Google sale del servidor, la clave se restringe en Google Cloud sólo a la Safe Browsing API, no por sitio web. Si un visitante pone su propia clave en Ajustes, se usa la suya directamente.

## Estructura

```
index.html
config.js        Configuración local (clave de Safe Browsing); no se sube al repositorio
config.example.js  Plantilla de config.js
api/safebrowsing.php  Proxy de Safe Browsing para la versión publicada (añade la clave en el servidor)
css/styles.css
js/mime.js       Parser MIME/RFC 5322 (multipart, base64, QP, RFC 2047/2231, charsets)
js/msg.js        Lector de .msg (MS-CFB, propiedades MAPI, RTF comprimido LZFu y HTML encapsulado) y conversión a .eml
js/analysis.js   Heurísticas, autenticación, dominios parecidos, antispam, IOCs y puntuación
js/dkim.js       Verificación criptográfica DKIM (RFC 6376/8301/8463) con WebCrypto
js/safebrowsing.js  Google Safe Browsing v5 con prefijos de hash (canonicalización y expresiones según la especificación)
js/online.js     DNS-over-HTTPS, RDAP (WHOIS), listas negras, Safe Browsing y hallazgos en línea
js/qr.js         Detección de códigos QR (BarcodeDetector o jsQR)
js/ai.js         Prompt/Summarizer/Translator/LanguageDetector con límites de tiempo
js/app.js        Interfaz
js/vendor/jsQR.js  jsQR 1.4.0 (Apache-2.0)
samples/         Correos de ejemplo
```

`mime.js`, `msg.js`, `analysis.js`, `dkim.js`, `safebrowsing.js` y `online.js` también funcionan en Node 18 o superior. La canonicalización de Safe Browsing se ha contrastado con los ejemplos de la especificación de Google. El verificador DKIM se ha contrastado con firmas generadas por `dkimpy`, en todas las combinaciones de algoritmo y canonicalización. El lector de `.msg` se ha contrastado con `extract-msg` sobre ficheros generados por Outlook: asunto, texto, HTML (enlaces idénticos), adjuntos (mismo SHA-256) y Content-ID.

## Limitaciones

- En los `.msg` no se puede verificar DKIM y el cuerpo es el que guarda Outlook, no el original byte a byte.
- Los RTF que no encapsulan HTML ni texto (RTF nativo) se convierten a texto plano sin formato.
- No valida criptográficamente la cadena ARC.
- La puntuación es heurística y orientativa: un correo legítimo de marketing puede sumar puntos, y un phishing bien hecho puede pasar SPF, DKIM y DMARC.
