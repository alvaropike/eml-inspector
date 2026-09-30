/*
 * Plantilla de configuración: cópiala como config.js y pon tu clave.
 *
 * safeBrowsingKey: clave de API de Google Cloud con la Safe Browsing API activada.
 * Si el campo «Clave de Safe Browsing» de la pestaña DNS y WHOIS tiene una clave,
 * se usa esa en lugar de esta.
 *
 * No compartas este fichero con la clave puesta.
 * Tras editarlo, recarga la página con Ctrl+F5.
 */
window.EML_CONFIG = {
  safeBrowsingKey: '',
  // En el servidor publicado (PHP): consulta Safe Browsing a través de api/safebrowsing.php,
  // que añade la clave del sitio. Lo escribe el despliegue; en local no hace falta.
  // safeBrowsingProxy: 'api/safebrowsing.php',
};
