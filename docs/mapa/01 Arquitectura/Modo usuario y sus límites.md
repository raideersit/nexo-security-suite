*Tipo: Concepto*

# Modo usuario y sus límites

Todo funciona en modo usuario: sin un driver de kernel firmado el sistema **detecta y reacciona**, pero no **previene**. Limitaciones conocidas:
- [Tiempo real](../03%20Funciones/Tiempo%20real.md): avisa *después* de que el archivo se escribió.
- No hay detección de rootkits ni minifiltro (fuera de alcance).
- Un atacante con permisos de administrador puede borrar la carpeta de copias ([Copia versionada](../03%20Funciones/Copia%20versionada.md)) o apagar el servicio.
- La aprobación con UAC solo protege contra procesos no elevados ([Vista previa, token y aprobación](Vista%20previa%2C%20token%20y%20aprobaci%C3%B3n.md)).

Nexo **complementa** a Microsoft Defender, no lo reemplaza. Todo el proyecto es 100 % gratuito (sin servicios de pago): por eso el motor es ClamAV y la VPN usa el cliente oficial de WireGuard.
