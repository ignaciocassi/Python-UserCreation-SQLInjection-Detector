import re
import logging

class SQLInjectionDetector:
    def __init__(self):
        # Configuración de logging para mostrar alertas en la terminal
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
        # Patrones comunes de inyección SQL
        self.patterns = [
            r"(\bor\b|\band\b)",     # Condiciones lógicas básicas
            r"(--|\#)",               # Comentarios SQL
            r"(\bunion\b|\bselect\b)",# Keywords peligrosas
            r"(\bdrop\b|\bdelete\b)", # Manipulación directa de datos
            r";",                     # Final de consulta
        ]
    
    def check_for_injection(self, user_input):
        """
        Verifica si la entrada del usuario contiene patrones de inyección SQL.
        """
        for pattern in self.patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                logging.warning(f"Posible intento de inyección SQL detectado: {user_input}")
                return True
        return False
