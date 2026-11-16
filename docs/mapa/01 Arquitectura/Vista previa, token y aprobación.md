*Tipo: Concepto*

# Vista previa, token y aprobación

Todo lo que **cambia algo** (firewall, VPN, carpetas protegidas, cuarentena, limpieza, reponer señuelos) sigue el mismo flujo:

```mermaid
sequenceDiagram
  participant V as Ventana
  participant S as Servicio
  participant T as Bandeja (elevada)
  participant U as UAC
  V->>S: x.previsualizar(parámetros)
  S-->>V: plan descrito + token (caduca)
  V->>V: la persona lee el plan
  V->>T: nexo-tray.exe --aplicar tipo token --pipe nombre (runas)
  T->>U: aviso de UAC (escritorio seguro)
  U-->>T: aceptado
  T->>S: x.aplicar(token) con token ELEVADO
  S->>S: PoliticaDeAprobacion valida; aplica solo ese plan; relee el estado
  S-->>T: resultado + nota en el vault
```

## Por qué así
- **Vista previa**: no se cambia nada sin enseñar antes qué se va a hacer.
- **Token de un solo uso y con caducidad**: aplicar ejecuta *solo* el plan guardado bajo ese token. El cliente no puede colar parámetros nuevos.
- **UAC como aprobación fuera de banda**: el aviso sale en el escritorio seguro, que un proceso normal del usuario no puede pulsar ni simular. `PoliticaDeAprobacion` exige un token **elevado** al aplicar.
- Límite conocido: protege frente a procesos **no elevados**; uno ya elevado puede todo.

## Detalles que importan
- La ventana busca `nexo-tray.exe` junto a ella y, si no está, en la carpeta hermana `tray` (corregido el 2026-11-15 al probar la VPN).
- `LanzadorElevado` se niega a elevar un ejecutable en una carpeta que el usuario pueda modificar (`UbicacionSegura`).

Relacionado: [Bandeja del sistema](../04%20Interfaces/Bandeja%20del%20sistema.md) · [Ventana principal](../04%20Interfaces/Ventana%20principal.md) · [Servicio NexoService](../03%20Funciones/Servicio%20NexoService.md) · [Identidad del llamador](Identidad%20del%20llamador.md)
