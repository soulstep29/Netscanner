[README.txt](https://github.com/user-attachments/files/28145783/README.txt)
#  NetScanner

Herramienta de análisis de red desarrollada en Python para entornos de laboratorio y redes autorizadas.

---

##  Características

- Escaneo de hosts activos (Ping Sweep)
- Escaneo de puertos TCP
- Banner Grabbing
- Integración con Nmap
- Detección de sistema operativo
- Diagnóstico básico de red
- Exportación de resultados (JSON/TXT)
- Historial de escaneos

---

##  Requisitos

- Python 3.x
- nmap instalado en el sistema (opcional)
- Librería python-nmap (opcional)

Instalación:

```bash
pip install python-nmap

En Linux:

sudo apt install nmap


Uso

Ejecutar el programa:

python3 netscanner.py
  Menú principal
1 → Escaneo de hosts (ping sweep)
2 → Escaneo de puertos TCP
3 → Escaneo con Nmap
4 → Captura de banners
5 → Información del sistema
6 → Diagnóstico de red
7 → Puertos comunes
8 → Detección de sistema operativo
9 → Escaneo de red externa autorizada
H → Historial
E → Exportar resultados
Q → Salir

![Menú principal](menu.png)
<img width="735" height="566" alt="menu" src="https://github.com/user-attachments/assets/c713a966-f354-4803-8b39-ea8aa0f24a3a" />





Aviso legal

Esta herramienta debe utilizarse únicamente en redes propias o con autorización explícita. El uso no autorizado puede ser ilegal.

Autor
GitHub: https://github.com/soulstep29
