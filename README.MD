# SQL Injection Prevention Server

Este proyecto es un servidor en Python basado en Flask que se conecta a una base de datos y ofrece protección contra inyecciones SQL. Mediante la implementación de una biblioteca personalizada (`SQLInjectionDetector`), el servidor revisa las entradas de usuario antes de interactuar con la base de datos, detectando patrones comunes de inyección SQL y generando alertas en tiempo real en la terminal.

## Características

- **Prevención de inyecciones SQL**: Utiliza consultas preparadas mediante SQLAlchemy para gestionar las interacciones con la base de datos de forma segura.
- **Sistema de alertas en tiempo real**: La biblioteca `SQLInjectionDetector` analiza las entradas del usuario en busca de patrones de inyección SQL y emite una alerta en la terminal cuando detecta una entrada sospechosa.
- **Servidor web con Flask**: Proporciona rutas HTTP seguras para agregar y recuperar usuarios de la base de datos.

## Requisitos

- Python 3.x
- Flask
- Flask-SQLAlchemy

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tu_usuario/sql-injection-prevention-server.git
   cd sql-injection-prevention-server


## Librerias 

# SQL Injection Prevention Server

Este proyecto es un servidor Flask diseñado para prevenir ataques de inyección SQL y mejorar la seguridad de una base de datos. Implementa múltiples técnicas de seguridad, como validación de entradas, autenticación básica, limitación de solicitudes y registro de intentos de ataque. Además, se recomienda configurarlo para HTTPS en un entorno de producción.

## Requisitos

Para que el servidor funcione correctamente, se requieren algunas librerías y módulos de Python. A continuación, se explica la función de cada uno y cómo instalarlos.

### Dependencias y Librerías

1. **Flask** (y módulos `request`, `jsonify`, `abort`)
   - **Función**: `Flask` es el framework principal para crear aplicaciones web en Python. Utilizamos `request` para manejar solicitudes HTTP, `jsonify` para convertir diccionarios de Python a respuestas JSON, y `abort` para manejar errores de solicitud.
   - **Instalación**:
     ```bash
     pip install Flask
     ```

2. **Flask-SQLAlchemy**
   - **Función**: `SQLAlchemy` es un ORM (Object-Relational Mapper) que simplifica las interacciones con la base de datos. La extensión `Flask-SQLAlchemy` facilita su uso en aplicaciones Flask.
   - **Instalación**:
     ```bash
     pip install Flask-SQLAlchemy
     ```

3. **Flask-Limiter** (y módulo `get_remote_address`)
   - **Función**: `Flask-Limiter` permite limitar el número de solicitudes que una IP puede hacer en un intervalo de tiempo específico. Esto ayuda a proteger el servidor contra ataques de fuerza bruta y abuso de recursos.
   - **Instalación**:
     ```bash
     pip install Flask-Limiter
     ```

4. **pydantic** (y módulos `BaseModel`, `EmailStr`, `ValidationError`)
   - **Función**: `pydantic` permite validar que los datos de entrada cumplan con los formatos esperados. Por ejemplo, usamos `EmailStr` para asegurarnos de que el campo de correo electrónico sea válido.
   - **Instalación**:
     ```bash
     pip install pydantic
     ```

5. **re** (módulo de expresiones regulares)
   - **Función**: `re` permite trabajar con expresiones regulares para buscar y filtrar patrones en texto, utilizado aquí para detectar patrones comunes de inyección SQL.
   - **Instalación**: Este módulo es parte de la biblioteca estándar de Python, por lo que no necesita instalación.

6. **logging**
   - **Función**: `logging` permite registrar eventos, advertencias y errores en un archivo de log para facilitar la monitorización de la aplicación.
   - **Instalación**: Este módulo también es parte de la biblioteca estándar de Python, por lo que no requiere instalación adicional.

7. **werkzeug.security** (módulos `generate_password_hash`, `check_password_hash`)
   - **Función**: `werkzeug.security` incluye herramientas para manejar la seguridad de contraseñas, como la creación y verificación de hashes. Esto protege las contraseñas de los usuarios al guardarlas en una forma cifrada.
   - **Instalación**: `werkzeug` se instala automáticamente con Flask.

8. **functools.wraps**
   - **Función**: `wraps` de `functools` es útil para crear decoradores manteniendo la metadata de la función original.
   - **Instalación**: Este módulo es parte de la biblioteca estándar de Python, por lo que no necesita instalación.

### Instalación de Dependencias

Para instalar todas las dependencias necesarias de una vez, puedes ejecutar el siguiente comando:

```bash
pip install Flask Flask-SQLAlchemy Flask-Limiter pydantic
