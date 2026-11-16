*Tipo: Concepto*

# Identidad del llamador

El servicio corre como SYSTEM, pero para leer, mover o borrar archivos de una persona **actúa con la identidad de esa persona** (suplantación del pipe, `RunImpersonatedAsync`, que cruza los `await`).

Efecto: solo se puede listar o borrar lo que ese usuario podría listar o borrar por sí mismo; las carpetas base (AppData…) son las del perfil del llamador, no las de la cuenta del servicio. Sin identidad utilizable, se rechaza.

Aplica a [Limpieza de archivos basura](../03%20Funciones/Limpieza%20de%20archivos%20basura.md) y [Cuarentena](../03%20Funciones/Cuarentena.md). Por eso `ClienteDePipe` conecta por omisión con nivel *Impersonation*; es seguro porque solo SYSTEM y Administradores pueden crear el pipe ([Pipe IPC y su ACL](Pipe%20IPC%20y%20su%20ACL.md)).
