"""
Centinela: privacidad y extracción de indicadores de un reporte de phishing (Rol 2).

Qué hace con el texto que reenvía el afiliado:
 1. Saca los indicadores peligrosos (enlaces, dominios, teléfonos, cuentas).
 2. Guarda teléfonos y cuentas como hash HMAC + últimos dígitos (nunca el número completo).
 3. Oculta los datos personales del texto (cédula, correo, teléfono, tarjeta, nombre).
 4. Reemplaza la identidad del reportante por un seudónimo (REP-xxxx).

Reglas de seguridad:
 - NUNCA se abre ni se visita un enlace reportado; solo se lee como texto.
 - Los enlaces se muestran "desactivados" (hxxps://dominio[.]example).
 - En la demo, usar dominios reservados (.example, .test, .invalid) y una marca
   ficticia ("Seguro Social"); no usar logos ni textos reales del IESS.
Solo usa la biblioteca estándar de Python.
"""

import hashlib
import hmac
import os
import re
from urllib.parse import urlsplit

LARGO_MAXIMO = 2000

# Marca protegida -> dominios oficiales. "segurosocial" es la marca ficticia de la demo.
MARCAS_PROTEGIDAS = {
    "iess": ("iess.gob.ec",),
    "segurosocial": ("segurosocial.example",),
}
SUFIJOS_DOBLES = (".gob.ec", ".com.ec", ".org.ec", ".edu.ec", ".fin.ec", ".net.ec")

PATRON_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
PATRON_CORREO = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
PATRON_CUENTA = re.compile(r"(?:cuenta|cta\.?|deposit\w*|transfer\w*)\D{0,30}?(\d{8,14})\b", re.IGNORECASE)
PATRON_TARJETA = re.compile(r"\b(?:\d[ -]?){13,19}\b")
PATRON_TELEFONO = re.compile(r"(?:\+593[\s-]?9\d{8}|\b09\d{8}\b|\b0[2-7]\d{7}\b)")
PATRON_DIEZ_DIGITOS = re.compile(r"\b\d{10}\b")
PATRON_NOMBRE = re.compile(r"\b(Estimad[oa]|Sr\.|Sra\.|Señor|Señora)\s+((?:[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+\s?){1,3})")


# --- Hash y seudónimos --------------------------------------------------------
def obtener_clave():
    """La clave HMAC sale de una variable de entorno; nunca va escrita en el código."""
    clave = os.environ.get("AEGIS_HMAC_CLAVE")
    if not clave:
        raise RuntimeError("Falta la variable de entorno AEGIS_HMAC_CLAVE")
    return clave


def hash_valor(valor, clave):
    """Hash HMAC-SHA256 de un número (solo los dígitos). Es el mismo que usa el
    Guardián en 'valor_hash', por eso permite un vínculo verificable."""
    solo_digitos = re.sub(r"\D", "", str(valor))
    return hmac.new(clave.encode(), solo_digitos.encode(), hashlib.sha256).hexdigest()


def seudonimo_reportante(id_canal, clave):
    """El número o chat del reportante nunca se guarda: solo REP- + 12 caracteres."""
    return "REP-" + hmac.new(clave.encode(), str(id_canal).encode(), hashlib.sha256).hexdigest()[:12].upper()


# --- Validaciones ----------------------------------------------------------------
def es_cedula(numero):
    """Valida una cédula ecuatoriana de persona natural (módulo 10)."""
    if not re.fullmatch(r"\d{10}", numero):
        return False
    provincia, tercero = int(numero[:2]), int(numero[2])
    if not (1 <= provincia <= 24 or provincia == 30) or tercero >= 6:
        return False
    suma = 0
    for i, coef in enumerate([2, 1, 2, 1, 2, 1, 2, 1, 2]):
        p = int(numero[i]) * coef
        suma += p - 9 if p > 9 else p
    return (10 - suma % 10) % 10 == int(numero[9])


def es_tarjeta(texto):
    """Algoritmo de Luhn para números de tarjeta."""
    digitos = [int(d) for d in re.sub(r"\D", "", texto)]
    if not 13 <= len(digitos) <= 19:
        return False
    suma = 0
    for i, d in enumerate(reversed(digitos)):
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        suma += d
    return suma % 10 == 0


# --- Indicadores -----------------------------------------------------------------
def desactivar_url(url):
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def dominio_registrable(host):
    host = host.lower().strip(".")
    partes = host.split(".")
    n = 3 if host.endswith(SUFIJOS_DOBLES) else 2
    return ".".join(partes[-n:])


def revisar_suplantacion(host):
    """True si el dominio usa una marca protegida y NO es su dominio oficial."""
    host = host.lower()
    for marca, oficiales in MARCAS_PROTEGIDAS.items():
        if marca in host.replace("-", "").replace(".", ""):
            if not any(host == d or host.endswith("." + d) for d in oficiales):
                return marca
    return None


def mascara(numero, visibles=2):
    d = re.sub(r"\D", "", numero)
    return "*" * (len(d) - visibles) + d[-visibles:]


def extraer_indicadores(texto, clave):
    enlaces, dominios = [], set()
    for url in PATRON_URL.findall(texto):
        url = url.rstrip(".,;)")
        try:
            host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
        except ValueError:
            continue
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
            continue
        dominio = dominio_registrable(host)
        dominios.add(dominio)
        enlaces.append({"url_desactivada": desactivar_url("https://" + dominio), "dominio": dominio.replace(".", "[.]"),
                        "suplanta_marca": revisar_suplantacion(host)})
    texto = PATRON_URL.sub(" ", texto)
    cuentas = [{"hash": hash_valor(n, clave), "mascara": mascara(n, 4)} for n in PATRON_CUENTA.findall(texto)]
    numeros_cuenta = set(PATRON_CUENTA.findall(texto))
    telefonos = []
    for t in PATRON_TELEFONO.findall(texto):
        digitos = re.sub(r"\D", "", t)
        if digitos in numeros_cuenta or es_cedula(digitos):
            continue
        telefonos.append({"hash": hash_valor(digitos, clave), "mascara": mascara(digitos)})
    return {"enlaces": enlaces, "dominios": sorted(dominios), "telefonos": telefonos, "cuentas": cuentas}


# --- Ocultar datos personales ----------------------------------------------------
def ocultar_datos_personales(texto):
    texto = PATRON_CORREO.sub("[CORREO_OCULTO]", texto)
    texto = PATRON_URL.sub(lambda m: desactivar_url(m.group(0)), texto)
    texto = PATRON_TARJETA.sub(lambda m: "[TARJETA_OCULTA]" if es_tarjeta(m.group(0)) else m.group(0), texto)
    texto = PATRON_CUENTA.sub(lambda m: m.group(0).replace(m.group(1), "[CUENTA_" + mascara(m.group(1), 4) + "]"), texto)
    texto = PATRON_DIEZ_DIGITOS.sub(lambda m: "[CEDULA_OCULTA]" if es_cedula(m.group(0)) else m.group(0), texto)
    texto = PATRON_TELEFONO.sub("[TELEFONO_OCULTO]", texto)
    texto = PATRON_NOMBRE.sub(lambda m: m.group(1) + " [NOMBRE_OCULTO] ", texto)
    return re.sub(r"[ \t]{2,}", " ", texto).strip()


def procesar_reporte(texto, id_canal_reportante, provincia, clave):
    """Lo único que se guarda: texto oculto, indicadores, seudónimo y provincia."""
    if not texto or len(texto) > LARGO_MAXIMO:
        raise ValueError(f"El texto debe tener entre 1 y {LARGO_MAXIMO} caracteres")
    return {
        "reportante": seudonimo_reportante(id_canal_reportante, clave),
        "provincia": provincia,
        "indicadores": extraer_indicadores(texto, clave),
        "texto_oculto": ocultar_datos_personales(texto),
    }


# --- Agrupar reportes en campañas ---------------------------------------------
def grupos_por_indicadores(reportes):
    """Dos reportes son de la misma campaña si comparten un dominio, teléfono o cuenta."""
    padre = list(range(len(reportes)))

    def raiz(i):
        while padre[i] != i:
            padre[i] = padre[padre[i]]
            i = padre[i]
        return i

    dueno = {}
    for i, r in enumerate(reportes):
        ind = r["indicadores"]
        claves = ([("dom", d) for d in ind["dominios"]] + [("tel", t["hash"]) for t in ind["telefonos"]]
                  + [("cta", c["hash"]) for c in ind["cuentas"]])
        for k in claves:
            if k in dueno:
                padre[raiz(i)] = raiz(dueno[k])
            else:
                dueno[k] = i

    grupos = {}
    for i in range(len(reportes)):
        grupos.setdefault(raiz(i), []).append(reportes[i])

    return sorted(grupos.values(), key=len, reverse=True)


def agrupar_en_campanas(reportes, minimo_reportes=5, minimo_provincias=3):
    campanas = []
    for n, miembros in enumerate(grupos_por_indicadores(reportes), start=1):
        provincias = {}
        for m in miembros:
            provincias[m["provincia"]] = provincias.get(m["provincia"], 0) + 1
        aviso = len(miembros) >= minimo_reportes or len(provincias) >= minimo_provincias
        campanas.append({
            "campana_id": f"CEN-{n:03d}",
            "reportes": len(miembros),
            "provincias": provincias,
            "dominios": sorted({d for m in miembros for d in m["indicadores"]["dominios"]}),
            "cuentas_hash": sorted({c["hash"] for m in miembros for c in m["indicadores"]["cuentas"]}),
            "estado": "AVISO_A_AFILIADOS" if aviso else "EN_OBSERVACION",
        })
    return campanas
