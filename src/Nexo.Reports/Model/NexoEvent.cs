using System;
using System.Collections.Generic;

namespace Nexo.Reports.Model
{
    /// <summary>
    /// Unidad de informacion que los modulos publican y que Nexo.Reports convierte
    /// en una nota markdown. Es el unico contrato entre los modulos y el vault:
    /// ningun modulo sabe que existe Obsidian, ni que existen archivos .md.
    /// </summary>
    public sealed class NexoEvent
    {
        public NexoEvent(ModuloOrigen modulo, string tipo, string titulo)
        {
            if (string.IsNullOrWhiteSpace(tipo))
                throw new ArgumentException("El tipo de evento es obligatorio.", nameof(tipo));
            if (string.IsNullOrWhiteSpace(titulo))
                throw new ArgumentException("El titulo es obligatorio: es el nombre del archivo.", nameof(titulo));

            Modulo = modulo;
            Tipo = tipo;
            // Una sola linea: un salto de linea en un nombre de archivo crearia un encabezado falso en la nota.
            Titulo = TextoVisible.UnaLinea(titulo.Trim());
        }

        /// <summary>
        /// GUID del evento. Va al front matter para que la escritura sea idempotente:
        /// si un modulo reintenta tras un fallo, el writer detecta el id y no duplica.
        /// </summary>
        public Guid Id { get; init; } = Guid.NewGuid();

        /// <summary>Instante del evento con offset horario. Nunca se usa UTC a secas:
        /// el vault lo lee una persona, y en Chile el offset cambia dos veces al ano.</summary>
        public DateTimeOffset Fecha { get; init; } = DateTimeOffset.Now;

        public ModuloOrigen Modulo { get; }

        /// <summary>Una de las constantes de <see cref="TipoEvento"/>.</summary>
        public string Tipo { get; }

        /// <summary>Titulo legible, en una linea (ver <see cref="TextoVisible"/>). Se usa como parte del nombre de archivo, ya saneado.</summary>
        public string Titulo { get; }

        public Severidad Severidad { get; init; } = Severidad.Info;

        public Accion Accion { get; init; } = Accion.Ninguna;

        /// <summary>
        /// Campos adicionales que van al front matter YAML, en orden de insercion.
        /// Solo se aceptan escalares (string, numeros, bool, DateTimeOffset) y listas
        /// de string: el objetivo es que Dataview y el panel de propiedades de
        /// Obsidian los puedan tabular sin ambiguedad.
        /// </summary>
        public IDictionary<string, object?> Campos { get; } = new Dictionary<string, object?>(StringComparer.Ordinal);

        /// <summary>Entidades a las que esta nota enlaza. Generan los wikilinks y el grafo.</summary>
        public IList<EntidadRef> Entidades { get; } = new List<EntidadRef>();

        /// <summary>
        /// Cuerpo markdown opcional, ya formateado por el modulo (tablas, listas).
        /// Se inserta tal cual bajo el encabezado "Detalle". El writer no lo escapa:
        /// es responsabilidad del modulo no meter aqui datos que deban ir redactados.
        /// </summary>
        public string? Cuerpo { get; init; }

        public NexoEvent Con(string campo, object? valor)
        {
            Campos[campo] = valor;
            return this;
        }

        public NexoEvent EnlazaA(EntidadRef entidad)
        {
            Entidades.Add(entidad);
            return this;
        }
    }
}
