Regla YARA para la Identificación de SMOKE_LOADER
Descripción:
Esta regla YARA fue desarrollada para detectar la presencia de la carga maliciosa conocida como SMOKE_LOADER en archivos específicos identificados por su hash SHA-256: 24ca31f5b2c38b141f0c22d7f6fdf6cf558c24840cf215fafab0f337afa4bac2/. Además, se ha establecido una relación con otras familias de malware, incluyendo ASYNCRAT, AMADEY, y NJRAT, mediante el hash de importación (imphash): f34d5f2d4577ed6d9ceec516c1f5a74.

Relación con Otras Familias de Malware:
ASYNCRAT
AMADEY
NJRAT

Instrucciones de Uso:
Clona o descarga el repositorio.
Utiliza la regla YARA proporcionada en tus análisis de malware para identificar la presencia de SMOKE_LOADER.
Considera la relación con otras familias de malware mencionadas.
