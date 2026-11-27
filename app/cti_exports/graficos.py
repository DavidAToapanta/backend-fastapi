from io import BytesIO
from base64 import b64encode
from threading import Lock

bloqueo_graficos = Lock()


def como_imagen_svg(figura) -> str:
    salida = BytesIO()
    figura.savefig(salida, format="svg", bbox_inches="tight", metadata={"Date": None})
    return "data:image/svg+xml;base64," + b64encode(salida.getvalue()).decode("ascii")


def dibujar_graficos(mapa: dict, escenarios: list[tuple[str, str, str, str]]) -> tuple[str, str]:
    # Matplotlib comparte cachés de fuentes entre peticiones concurrentes.
    with bloqueo_graficos:
        from matplotlib.figure import Figure

        figura = Figure(figsize=(7.0, 2.5), layout="constrained")
        eje = figura.subplots()
        grafico = eje.imshow(mapa["matriz"], aspect="auto", cmap="YlGnBu", interpolation="nearest")
        dias = mapa["dias"]
        posiciones = list(range(0, len(dias), 5))
        eje.set_xticks(posiciones, [dias[i].strftime("%d/%m") for i in posiciones])
        eje.set_yticks([0, 6, 12, 18, 23])
        eje.set_xlabel("Día (UTC)")
        eje.set_ylabel("Hora")
        figura.colorbar(grafico, ax=eje, label="Eventos")
        horario = como_imagen_svg(figura)

        figura = Figure(figsize=(6.8, 1.85), layout="constrained")
        eje = figura.subplots()
        eje.set(xlim=(-0.5, 1.5), ylim=(-0.5, 1.5), xlabel="Impacto", ylabel="Probabilidad")
        impactos = ["Alto", "Crítico"]
        probabilidades = ["Media", "Alta"]
        eje.set_xticks([0, 1], impactos)
        eje.set_yticks([0, 1], probabilidades)
        eje.axhline(0.5, color="#9cb1b5", linewidth=0.8)
        eje.axvline(0.5, color="#9cb1b5", linewidth=0.8)
        for nombre, probabilidad, impacto, _ in escenarios:
            eje.text(impactos.index(impacto), probabilidades.index(probabilidad), nombre,
                     ha="center", va="center", color="#124f49", fontweight="bold")
        return horario, como_imagen_svg(figura)
