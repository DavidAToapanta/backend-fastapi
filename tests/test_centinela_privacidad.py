"""Pruebas de privacidad de Centinela (Rol 2).
Ejecutar desde la raíz del repositorio:  python -m unittest tests.test_centinela_privacidad -v
"""
import json
import unittest

from app.servicios.centinela_privacidad import (
    agrupar_en_campanas, es_cedula, hash_valor, ocultar_datos_personales, procesar_reporte)

CLAVE = "clave-solo-para-pruebas"

SMS = ("Estimado Juan Perez, su aporte al Seguro Social fue retenido. Actualice en "
       "https://segurosocial-pagos.example/validar o llame al 0991234567. "
       "Deposite $5 a la cuenta 2200123456 para liberar. Cedula 1710034065, correo juan@correo.test")


class PruebasCentinela(unittest.TestCase):

    def test_cedula_valida_e_invalida(self):
        self.assertTrue(es_cedula("1710034065"))
        self.assertFalse(es_cedula("1710034066"))

    def test_oculta_datos_personales(self):
        t = ocultar_datos_personales(SMS)
        for dato in ["1710034065", "juan@correo.test", "0991234567", "Juan Perez", "2200123456"]:
            self.assertNotIn(dato, t)
        self.assertIn("[CEDULA_OCULTA]", t)
        self.assertIn("[NOMBRE_OCULTO]", t)
        self.assertIn("hxxps://segurosocial-pagos[.]example", t)

    def test_oculta_tarjeta_con_luhn(self):
        self.assertIn("[TARJETA_OCULTA]", ocultar_datos_personales("Su tarjeta 4111 1111 1111 1111 fue bloqueada"))

    def test_extrae_indicadores_sin_guardar_numeros_completos(self):
        r = procesar_reporte(SMS, "+593990000001", "Pichincha", CLAVE)
        ind = r["indicadores"]
        self.assertEqual(ind["dominios"], ["segurosocial-pagos.example"])
        self.assertEqual(ind["enlaces"][0]["suplanta_marca"], "segurosocial")
        self.assertEqual(ind["cuentas"][0]["mascara"], "******3456")
        self.assertEqual(len(ind["telefonos"]), 1)
        guardado = json.dumps(r)
        for dato in ["2200123456", "0991234567", "1710034065", "+593990000001", "Juan Perez"]:
            self.assertNotIn(dato, guardado)
        self.assertTrue(r["reportante"].startswith("REP-"))

    def test_dominio_oficial_no_es_suplantacion(self):
        r = procesar_reporte("Ingrese a https://www.segurosocial.example/servicios", "x", "Azuay", CLAVE)
        self.assertIsNone(r["indicadores"]["enlaces"][0]["suplanta_marca"])

    def test_vinculo_verificable_con_guardian(self):
        r = procesar_reporte(SMS, "x", "Guayas", CLAVE)
        # El Guardián guarda el hash de la cuenta nueva con la misma clave y la misma función
        self.assertEqual(r["indicadores"]["cuentas"][0]["hash"], hash_valor("2200123456", CLAVE))

    def test_texto_muy_largo_se_rechaza(self):
        with self.assertRaises(ValueError):
            procesar_reporte("a" * 2001, "x", "Loja", CLAVE)

    def test_agrupa_por_indicador_compartido(self):
        r1 = procesar_reporte(SMS, "a", "Pichincha", CLAVE)
        r2 = procesar_reporte("Ultimo aviso: https://segurosocial-pagos.example/x", "b", "Guayas", CLAVE)
        r3 = procesar_reporte("Gane un premio en http://premios-falsos.test", "c", "Manabi", CLAVE)
        campanas = agrupar_en_campanas([r1, r2, r3], minimo_reportes=2)
        self.assertEqual(len(campanas), 2)
        self.assertEqual(campanas[0]["reportes"], 2)
        self.assertEqual(campanas[0]["estado"], "AVISO_A_AFILIADOS")
        self.assertEqual(campanas[1]["estado"], "EN_OBSERVACION")


if __name__ == "__main__":
    unittest.main()
