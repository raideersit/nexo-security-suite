*Tipo: Función*

# Enlaces y phishing

Revisa enlaces, mensajes, remitentes y códigos QR contra listas de phishing.

## Cómo funciona
`ExtractorDeEnlaces`, `AnalizadorDeMensajes`, `AnalizadorDeRemitente`, `LectorDeQr`, `Marcas` y `ListasDePhishing`. `AlmacenDeListas` descarga y guarda las listas públicas. Se ejecuta **en la ventana**, sin método del pipe.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Ui.Desktop](../02%20Proyectos/Nexo.Ui.Desktop.md)

## Interfaz
- Pestaña **Enlaces**.

## Notas que deja en Obsidian
Tipos de evento: `sitio-bloqueado`, `mensaje-revisado`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Todo es análisis local; solo la descarga de listas sale a internet.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
