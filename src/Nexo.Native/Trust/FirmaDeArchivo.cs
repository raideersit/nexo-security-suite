using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Nexo.Native.Trust
{
    public enum ResultadoDeFirma { Valida, Ausente, Invalida, NoSePudo }

    /// <summary>
    /// ¿Tiene el archivo una firma digital válida (Authenticode)? Usa WinVerifyTrust con la política genérica, sin ventana y sin red
    /// (no consulta revocaciones: solo caché). Los archivos de Windows suelen estar firmados por CATÁLOGO y no dentro del archivo:
    /// si la firma incrustada no está, se busca el catálogo por el hash del archivo (CryptCATAdmin) y se verifica con él; sin eso, casi
    /// todo System32 saldría «sin firma». No exige administrador. No lanza: lo que no se puede comprobar es «NoSePudo», nunca «Valida».
    /// </summary>
    public static class FirmaDeArchivo
    {
        private const uint WTD_UI_NONE = 2, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2, WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_REVOCATION_CHECK_NONE = 0x10, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
        private static Guid _genericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100), TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003), TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
        private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010), CERT_E_EXPIRED = unchecked((int)0x800B0101), CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109),
                          CERT_E_CHAINING = unchecked((int)0x800B010A), CERT_E_UNTRUSTEDTESTROOT = unchecked((int)0x800B010D), TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111),
                          CERT_E_REVOKED = unchecked((int)0x800B010C), TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);

        [StructLayout(LayoutKind.Sequential)] private struct WINTRUST_FILE_INFO { public uint cbStruct; public IntPtr pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }
        [StructLayout(LayoutKind.Sequential)] private struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct; public uint dwCatalogVersion; public IntPtr pcwszCatalogFilePath; public IntPtr pcwszMemberTag; public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile; public IntPtr pbCalculatedFileHash; public uint cbCalculatedFileHash; public IntPtr pcCatalogContext; public IntPtr hCatAdmin;
        }
        [StructLayout(LayoutKind.Sequential)] private struct WINTRUST_DATA
        {
            public uint cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData; public uint dwUIChoice; public uint fdwRevocationChecks; public uint dwUnionChoice;
            public IntPtr pUnion; public uint dwStateAction; public IntPtr hWVTStateData; public IntPtr pwszURLReference; public uint dwProvFlags; public uint dwUIContext; public IntPtr pSignatureSettings;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct CATALOG_INFO { public uint cbStruct; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile; }

        [DllImport("wintrust.dll", ExactSpelling = true)] private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, IntPtr data);
        [DllImport("wintrust.dll", SetLastError = true)] private static extern bool CryptCATAdminAcquireContext(out IntPtr hCatAdmin, IntPtr pgSubsystem, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint flags, ref IntPtr phPrevCatInfo);
        [DllImport("wintrust.dll", SetLastError = true)] private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO info, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);

        /// <summary>Verifica un archivo. <c>Codigo</c> es el HRESULT de WinVerifyTrust (0 = válida), o 0 si no se llegó a llamar.</summary>
        public static (ResultadoDeFirma Resultado, int Codigo) Verificar(string? ruta)
        {
            if (string.IsNullOrWhiteSpace(ruta) || !File.Exists(ruta)) return (ResultadoDeFirma.NoSePudo, 0);
            try
            {
                int r = VerificarIncrustada(ruta);
                if (r == 0) return (ResultadoDeFirma.Valida, 0);
                if (r == TRUST_E_NOSIGNATURE || r == TRUST_E_SUBJECT_FORM_UNKNOWN || r == TRUST_E_PROVIDER_UNKNOWN)
                {
                    int? c = VerificarPorCatalogo(ruta);
                    if (c == 0) return (ResultadoDeFirma.Valida, 0);
                    if (c is null) return (ResultadoDeFirma.Ausente, r); // ningún catálogo lo menciona
                    return (Clasificar(c.Value), c.Value);
                }
                return (Clasificar(r), r);
            }
            catch { return (ResultadoDeFirma.NoSePudo, 0); }
        }

        private static ResultadoDeFirma Clasificar(int h) => h switch
        {
            0 => ResultadoDeFirma.Valida,
            TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => ResultadoDeFirma.Ausente,
            TRUST_E_BAD_DIGEST or CERT_E_EXPIRED or CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING or CERT_E_UNTRUSTEDTESTROOT or TRUST_E_EXPLICIT_DISTRUST or CERT_E_REVOKED or TRUST_E_SUBJECT_NOT_TRUSTED => ResultadoDeFirma.Invalida,
            _ => ResultadoDeFirma.NoSePudo, // archivo bloqueado, sin permiso, etc.: no es «inválida»
        };

        private static int VerificarIncrustada(string ruta)
        {
            IntPtr path = Marshal.StringToHGlobalUni(ruta);
            var fi = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
            IntPtr pf = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fi, pf, false);
            try { return Llamar(WTD_CHOICE_FILE, pf); }
            finally { Marshal.FreeHGlobal(pf); Marshal.FreeHGlobal(path); }
        }

        /// <summary>null = ningún catálogo contiene el hash del archivo; un número distinto de 0 = no se pudo / falló.</summary>
        private static int? VerificarPorCatalogo(string ruta)
        {
            if (!CryptCATAdminAcquireContext(out IntPtr admin, IntPtr.Zero, 0)) return 1;
            try
            {
                using var fs = new FileStream(ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                IntPtr h = fs.SafeFileHandle.DangerousGetHandle();
                uint n = 0;
                CryptCATAdminCalcHashFromFileHandle(h, ref n, null, 0);
                if (n == 0 || n > 256) return 1;
                var hash = new byte[n];
                if (!CryptCATAdminCalcHashFromFileHandle(h, ref n, hash, 0)) return 1;
                IntPtr prev = IntPtr.Zero;
                IntPtr cat = CryptCATAdminEnumCatalogFromHash(admin, hash, n, 0, ref prev);
                if (cat == IntPtr.Zero) return null;
                try
                {
                    var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>(), wszCatalogFile = "" };
                    if (!CryptCATCatalogInfoFromContext(cat, ref info, 0)) return 1;
                    var tag = new StringBuilder();
                    foreach (byte b in hash) tag.Append(b.ToString("X2"));
                    IntPtr pCat = Marshal.StringToHGlobalUni(info.wszCatalogFile), pTag = Marshal.StringToHGlobalUni(tag.ToString()), pMem = Marshal.StringToHGlobalUni(ruta);
                    IntPtr pHash = Marshal.AllocHGlobal(hash.Length);
                    Marshal.Copy(hash, 0, pHash, hash.Length);
                    var ci = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(), pcwszCatalogFilePath = pCat, pcwszMemberTag = pTag, pcwszMemberFilePath = pMem,
                        pbCalculatedFileHash = pHash, cbCalculatedFileHash = n, hCatAdmin = admin,
                    };
                    IntPtr pc = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                    Marshal.StructureToPtr(ci, pc, false);
                    try { return Llamar(WTD_CHOICE_CATALOG, pc); }
                    finally { Marshal.FreeHGlobal(pc); Marshal.FreeHGlobal(pHash); Marshal.FreeHGlobal(pMem); Marshal.FreeHGlobal(pTag); Marshal.FreeHGlobal(pCat); }
                }
                finally { CryptCATAdminReleaseCatalogContext(admin, cat, 0); }
            }
            finally { CryptCATAdminReleaseContext(admin, 0); }
        }

        private static int Llamar(uint eleccion, IntPtr union)
        {
            var d = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(), dwUIChoice = WTD_UI_NONE, fdwRevocationChecks = 0, dwUnionChoice = eleccion, pUnion = union,
                dwStateAction = WTD_STATEACTION_VERIFY, dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };
            IntPtr pd = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(d, pd, false);
            try
            {
                int r = WinVerifyTrust(new IntPtr(-1), ref _genericVerifyV2, pd);
                var cerrar = Marshal.PtrToStructure<WINTRUST_DATA>(pd);
                cerrar.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(cerrar, pd, false);
                WinVerifyTrust(new IntPtr(-1), ref _genericVerifyV2, pd);
                return r;
            }
            finally { Marshal.FreeHGlobal(pd); }
        }
    }
}
