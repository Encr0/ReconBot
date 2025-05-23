# Imagen base oficial de Python
FROM python:3.11-slim

# Establecer el directorio de trabajo en el contenedor
WORKDIR /app

# Copiar requirements y luego instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del proyecto
COPY . .

# Exponer el puerto en el que corre Django
EXPOSE 8000

# Comando por defecto para ejecutar el servidor de desarrollo
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
