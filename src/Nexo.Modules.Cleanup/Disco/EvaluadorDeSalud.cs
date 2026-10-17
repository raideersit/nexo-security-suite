using System;
using System.Collections.Generic;
using System.Globalization;
using Nexo.Reports.Model;

namespace Nexo.Modules.Cleanup.Disco
{
    /// <summary>
    /// Decide cuando un disco merece una alerta.
    ///
    /// PredictFailure es binario y llega tarde: cuando se activa, el disco ya esta
    /// mal. Los atributos que de verdad anticipan el fallo, segun el conjunto de
    /// datos publico de Backblaze, son cinco (Salida 4, §1.6). Esos son los que se
    /// evaluan aqui, con los umbrales de la tabla del diseno.
    ///
    /// "Creciendo" necesita una lectura anterior; sin ella, un atributo que solo
    /// debe alertar al crecer (188) no alerta, y los demas alertan con severidad
    /// menor. No se asume nada que no se haya medido.
    /// </summary>
    public static class EvaluadorDeSalud
    {
        public static EvaluacionDeSalud Evaluar(LecturaDeDisco actual, LecturaDeDisco? anterior = null)
        {
            if (actual is null) throw new ArgumentNullException(nameof(actual));

            var alertas = new List<string>();
            Severidad peor = Severidad.Info;

            void Alerta(Severidad s, string texto)
            {
                alertas.Add(texto);
                if (s > peor) peor = s;
            }

            // 05 — Sectores reasignados: > 0 y creciendo.
            if (Conteo(actual, 5, out ulong reasignados) && reasignados > 0)
            {
                bool crece = Crece(actual, anterior, 5);
                Alerta(crece ? Severidad.Alta : Severidad.Media,
                       "Sectores reasignados (05): " + N(reasignados) + (crece ? ", y estan aumentando" : ""));
            }

            // 187 — Errores incorregibles reportados: > 0.
            if (Conteo(actual, 187, out ulong incorregibles) && incorregibles > 0)
                Alerta(Severidad.Alta, "Errores incorregibles reportados (187): " + N(incorregibles));

            // 188 — Tiempos de espera de comandos: solo si crecen.
            if (Crece(actual, anterior, 188))
                Alerta(Severidad.Media, "Tiempos de espera de comandos (188) en aumento");

            // 197 — Sectores pendientes: > 0. El mas predictivo de los cinco.
            if (Conteo(actual, 197, out ulong pendientes) && pendientes > 0)
            {
                bool crece = Crece(actual, anterior, 197);
                Alerta(crece ? Severidad.Critica : Severidad.Alta,
                       "Sectores pendientes de reasignar (197): " + N(pendientes) + (crece ? ", y estan aumentando" : ""));
            }

            // 198 — Incorregibles fuera de linea: > 0.
            if (Conteo(actual, 198, out ulong offline) && offline > 0)
                Alerta(Severidad.Alta, "Sectores incorregibles fuera de linea (198): " + N(offline));

            if (actual.PrediccionDeFallo == true)
            {
                alertas.Insert(0, "El disco activo su bandera de prediccion de fallo");
                peor = Severidad.Critica;
            }

            return new EvaluacionDeSalud(peor, alertas);
        }

        private static bool Conteo(LecturaDeDisco l, byte id, out ulong valor)
        {
            AtributoSmart? a = l.Atributo(id);
            valor = a?.Crudo ?? 0;
            return a is not null;
        }

        private static bool Crece(LecturaDeDisco actual, LecturaDeDisco? anterior, byte id)
        {
            if (anterior is null) return false;
            AtributoSmart? a = actual.Atributo(id);
            AtributoSmart? b = anterior.Atributo(id);
            return a is not null && b is not null && a.Crudo > b.Crudo;
        }

        private static string N(ulong v) => v.ToString(CultureInfo.InvariantCulture);
    }
}
