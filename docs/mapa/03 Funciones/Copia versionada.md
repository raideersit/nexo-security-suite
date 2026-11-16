*Tipo: Función*

# Copia versionada

Copias de seguridad con versiones de Documentos, Escritorio e Imágenes en un destino local (por ejemplo un disco externo).

## Cómo funciona
Guarda el contenido por huella (lo repetido se reutiliza) y una lista por instantánea; conserva N versiones. Si el destino desaparece a mitad, la copia **falla** y no queda «en curso» ni a medias (vigilante del destino). Detecta copias sospechosas (cambios masivos, típicos de cifrado) y puede dar una por buena con `descartar`.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `copia.estado`
- `copia.hacer`
- `copia.descartar`

## Interfaz
- Pestaña **Copias**: hacer copia, ver versiones, restaurar (la restauración la hace la ventana con los permisos de la persona).
- [Bandeja del sistema](../04%20Interfaces/Bandeja%20del%20sistema.md): acceso rápido.

## Notas que deja en Obsidian
Tipos de evento: `copia-hecha`, `copia-sospechosa`, `copia-fallida`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- No hay método para restaurar a propósito: el servicio corre como SYSTEM y no debe escribir donde le diga un cliente.
- El destino es siempre el configurado, nunca una ruta del cliente.
- La carpeta de copias solo la cambian SYSTEM y administradores (aun así, un administrador podría borrarla).

## Configuración
`Nexo:Copia` (Activo, Destino, Versiones, CadaHoras, Carpetas). Apagada por omisión.

## Estado
Copia real probada el 2026-11-15: 60 835 archivos, 12,66 GB en `D:`, 12 min. El vigilante del destino se probó desenchufando un USB de verdad.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
