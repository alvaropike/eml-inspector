<?php
/*
 * Proxy de Google Safe Browsing (API v5, hashes.search) para la versión publicada.
 * El navegador envía sólo prefijos de hash de 4 bytes; aquí se añade la clave del sitio,
 * que nunca llega al navegador, y se devuelve la respuesta de Google tal cual (protobuf).
 *
 * La clave se lee de la variable de entorno GOOGLE_SAFE_BROWSER o de sb-key.php
 * (<?php return 'clave';), que escribe el despliegue y .htaccess impide descargar.
 */

const ENDPOINT = 'https://safebrowsing.googleapis.com/v5/hashes:search';
const MAX_PREFIXES = 400;     // igual que BATCH en js/safebrowsing.js
const RATE_LIMIT = 120;       // peticiones por IP…
const RATE_WINDOW = 600;      // …cada 10 minutos

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function fail($status, $message) {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['error' => ['code' => $status, 'message' => $message]], JSON_UNESCAPED_UNICODE);
  exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') fail(405, 'Método no permitido');

// Sólo desde la propia web: los navegadores marcan las peticiones de otros sitios.
$site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
if ($site !== '' && $site !== 'same-origin') fail(403, 'Origen no permitido');
$host = strtolower($_SERVER['HTTP_HOST'] ?? '');
foreach (['HTTP_ORIGIN', 'HTTP_REFERER'] as $h) {
  if (!empty($_SERVER[$h]) && strtolower((string) parse_url($_SERVER[$h], PHP_URL_HOST)) !== preg_replace('/:\d+$/', '', $host)) {
    fail(403, 'Origen no permitido');
  }
}

// Límite por IP, en un fichero temporal por IP y ventana.
$window = intdiv(time(), RATE_WINDOW);
$counter = sys_get_temp_dir() . '/eml-sb-' . hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '') . '|' . $window);
$hits = (int) @file_get_contents($counter) + 1;
@file_put_contents($counter, (string) $hits, LOCK_EX);
if ($hits > RATE_LIMIT) {
  header('Retry-After: ' . (RATE_WINDOW - time() % RATE_WINDOW));
  fail(429, 'Demasiadas consultas; inténtalo en unos minutos');
}

// hashPrefixes repetido: PHP sólo conserva el último en $_GET, así que se lee la query a mano.
$prefixes = [];
foreach (explode('&', $_SERVER['QUERY_STRING'] ?? '') as $pair) {
  if ($pair === '') continue;
  [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
  if (rawurldecode($name) !== 'hashPrefixes') continue;
  $value = rawurldecode($value);
  if (!preg_match('~^[A-Za-z0-9+/]{6}==$~', $value)) fail(400, 'Prefijo de hash no válido');
  $prefixes[$value] = true;
}
if (!$prefixes) fail(400, 'Faltan prefijos de hash');
if (count($prefixes) > MAX_PREFIXES) fail(400, 'Demasiados prefijos de hash');

$key = getenv('GOOGLE_SAFE_BROWSER') ?: (is_file(__DIR__ . '/sb-key.php') ? (include __DIR__ . '/sb-key.php') : '');
if (!is_string($key) || trim($key) === '') fail(503, 'Safe Browsing no está configurado en el servidor');

$query = 'key=' . rawurlencode(trim($key));
foreach (array_keys($prefixes) as $p) $query .= '&hashPrefixes=' . rawurlencode($p);

$ch = curl_init(ENDPOINT . '?' . $query);
curl_setopt_array($ch, [
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_HEADER => false,
  CURLOPT_CONNECTTIMEOUT => 5,
  CURLOPT_TIMEOUT => 15,
]);
$body = curl_exec($ch);
if ($body === false) fail(502, 'No se pudo contactar con Google Safe Browsing');
$status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
$type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: 'application/octet-stream';

// Los errores de Google no incluyen la clave; se reenvían para que el cliente los explique.
http_response_code($status);
header('Content-Type: ' . $type);
echo $body;
