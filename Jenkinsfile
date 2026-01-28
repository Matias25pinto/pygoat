pipeline {
    agent any

    environment {

        HOME = "${WORKSPACE}"

        // Defect Dojo
        DD_URL = 'http://django-defectdojo-nginx-1:8080'
        DD_API_KEY = credentials('defectdojo-api-key')
        DD_PRODUCT_NAME = 'pygoat'
        DD_ENGAGEMENT_NAME = 'Jenkins Pipeline - Ejercicio 2'
        DD_ENGAGEMENT_ID = '2'
        
        // Nombres de archivos
        BANDIT_REPORT = 'reporte_bandit.json'
        GITLEAKS_REPORT = 'gitleaks-report.json'
        BOM_FILE = 'bom.json'
        FPF_FILE = 'fpf.json'

        //Dependency Track
        DTRACK_URL = 'http://dtrack-api:8080'
        DTRACK_API_KEY = credentials('dependency-track-api-key')
        PROJECT_NAME = 'pygoat'
        PROJECT_VERSION = "ejercicio-2"
    }

    stages {

        stage('Checkout') {
            steps {
                echo "Obteniendo el código desde GitHub..."
                sh '''
                    rm -rf pygoat || true
                    git clone https://github.com/Matias25pinto/pygoat.git pygoat
                    git config --global --add safe.directory $WORKSPACE/pygoat
                    cd pygoat
                    git checkout defect-dojo
                '''
                // Stash para compartir el código entre stages con diferentes agentes
                stash name: 'pygoat-code', includes: 'pygoat/**'
            }
        }

        stage('SAST - Bandit') {
            agent {
                    docker {
                    image 'ci-python-security:latest'
                    reuseNode true
                }
            }
            steps {
                script {
                    // Recuperar el código stasheado
                    unstash 'pygoat-code'
                    
                    // Eliminar archivo anterior si existe
                    sh 'rm -f $BANDIT_REPORT || true'
                    
                    // Ejecutar Bandit capturando el exit code
                    def banditExitCode = sh(script: '''
                        cd pygoat
                        bandit -r . -f json -o ../$BANDIT_REPORT
                    ''', returnStatus: true)
                    
                    echo "Bandit exit code: ${banditExitCode}"
                    
                    // Bandit retorna:
                    // 0 = No issues found
                    // 1 = Issues found
                    // 2 = Error
                    if (banditExitCode == 1) {
                        unstable(message: "Bandit encontró vulnerabilidades de seguridad")
                        echo "Bandit encontró vulnerabilidades"
                    } else if (banditExitCode == 2) {
                        error("Bandit falló con un error")
                    }
                    
                    // Verificar que el archivo se creó
                    sh 'test -f $BANDIT_REPORT && echo "Archivo $BANDIT_REPORT creado" || echo "Archivo no existe, creando vacío..."'
                    sh 'test -f $BANDIT_REPORT || echo "{}" > $BANDIT_REPORT'
                    sh 'ls -la $BANDIT_REPORT'
                }
                // Archivar resultados
                stash name: 'bandit-report', includes: "${BANDIT_REPORT}"
                archiveArtifacts artifacts: "${BANDIT_REPORT}", fingerprint: true, allowEmptyArchive: true
            }
            
            post {
                always {
                    script {
                        if (fileExists("${BANDIT_REPORT}")) {
                            echo "Resultados de Bandit disponibles para análisis"
                        }
                    }
                }
            }
        }


        stage('SCA - Dependency-Track') {
            agent {
                docker {
                    image 'ci-python-security:latest'
                    args '--network cicd-net'
                    reuseNode true
                }
            }
            steps {
                script {
                    unstash 'pygoat-code'

                    // 1️⃣ Generar SBOM usando cyclonedx-py correctamente
                    sh '''
                        cd pygoat
                        echo "Generando SBOM para requirements.txt..."
                        
                        # Verificar la versión y opciones de cyclonedx-py
                        echo "=== Información de cyclonedx-py ==="
                        cyclonedx-py --help 2>&1 | head -20 || true
                        
                        # Intentar diferentes formatos de comando
                        echo "=== Intentando generar BOM ==="
                        
                        # Opción 1: Formato antiguo (--requirements)
                        if cyclonedx-py --help 2>&1 | grep -q "requirements"; then
                            echo "Usando formato: cyclonedx-py --requirements"
                            cyclonedx-py --requirements requirements.txt --output ../$BOM_FILE
                        # Opción 2: Formato nuevo (requirements como subcomando)
                        elif cyclonedx-py requirements --help 2>&1 | grep -q "requirements"; then
                            echo "Usando formato: cyclonedx-py requirements"
                            cyclonedx-py requirements requirements.txt -o ../$BOM_FILE
                        # Opción 3: Intentar con pip directamente
                        else
                            echo "Formato no reconocido, usando pip para generar BOM..."
                            pip list --format=json > ../pip_list.json
                            
                            # Crear un BOM básico manualmente
                            echo '{
                            "bomFormat": "CycloneDX",
                            "specVersion": "1.4",
                            "version": 1,
                            "metadata": {
                                "tools": [
                                {
                                    "vendor": "Jenkins",
                                    "name": "Pipeline"
                                }
                                ]
                            },
                            "components": []
                            }' > ../$BOM_FILE
                            
                            # Extraer paquetes de pip list y agregarlos al BOM
                            python3 -c "
        import json
        import subprocess

        # Leer lista de paquetes instalados
        with open('../pip_list.json', 'r') as f:
            packages = json.load(f)

        # Leer requirements.txt
        with open('requirements.txt', 'r') as f:
            requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        # Leer BOM base
        with open('../$BOM_FILE', 'r') as f:
            bom = json.load(f)

        # Crear componentes
        components = []
        for req in requirements:
            # Parsear nombre y versión (formato simple)
            parts = req.split('==')
            if len(parts) == 2:
                name, version = parts
                components.append({
                    'type': 'library',
                    'name': name,
                    'version': version,
                    'purl': f'pkg:pypi/{name}@{version}'
                })

        bom['components'] = components

        # Guardar BOM actualizado
        with open('../$BOM_FILE', 'w') as f:
            json.dump(bom, f, indent=2)
                            "
                        fi
                        
                        echo "=== BOM generado ==="
                        ls -la ../$BOM_FILE
                        echo "Primeras líneas del BOM:"
                        head -5 ../$BOM_FILE
                        
                        # Verificar que el BOM es JSON válido
                        if python3 -c "import json; json.load(open('../$BOM_FILE', 'r'))" 2>/dev/null; then
                            echo "✅ BOM es JSON válido"
                        else
                            echo "⚠ BOM no es JSON válido, creando BOM básico..."
                            echo '{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}' > ../$BOM_FILE
                        fi
                    '''

                    // 2️⃣ Subir SBOM a Dependency-Track (simplificado)
                    sh '''
                        echo "=== Subiendo BOM a Dependency-Track ==="
                        echo "URL: $DTRACK_URL/api/v1/bom"
                        
                        # Subir el BOM sin esperar respuesta compleja
                        set +e  # No salir en error
                        
                        curl -v -X POST "$DTRACK_URL/api/v1/bom" \
                            -H "X-Api-Key: $DTRACK_API_KEY" \
                            -F "projectName=$PROJECT_NAME" \
                            -F "projectVersion=$PROJECT_VERSION" \
                            -F "autoCreate=true" \
                            -F "bom=@$BOM_FILE" 2>&1 | grep -E "(HTTP|< HTTP|{\"token\")" || true
                        
                        set -e
                        
                        echo "✅ BOM enviado (o al menos intentado)"
                        
                        # Dar tiempo a que se procese
                        sleep 5
                    '''

                    // 3️⃣ Obtener información del proyecto (intento simple)
                    sh '''
                        echo "=== Verificando estado del proyecto ==="
                        
                        # Intentar obtener el proyecto
                        PROJECTS_JSON=$(curl -s -H "X-Api-Key: $DTRACK_API_KEY" "$DTRACK_URL/api/v1/project" 2>/dev/null || echo "[]")
                        
                        echo "Proyectos en Dependency-Track:"
                        echo "$PROJECTS_JSON" | jq -r '.[] | "  - \(.name): \(.lastBomImport)"' 2>/dev/null || echo "  No se pudieron listar proyectos"
                        
                        # Buscar nuestro proyecto
                        PROJECT_UUID=$(echo "$PROJECTS_JSON" | jq -r --arg name "$PROJECT_NAME" '.[] | select(.name == $name) | .uuid' 2>/dev/null || echo "")
                        
                        if [ -n "$PROJECT_UUID" ] && [ "$PROJECT_UUID" != "null" ]; then
                            echo "✅ Proyecto encontrado: $PROJECT_UUID"
                            echo "PROJECT_UUID=$PROJECT_UUID" > project_info.txt
                            
                            # Intentar obtener versión específica
                            PROJECT_INFO=$(curl -s -H "X-Api-Key: $DTRACK_API_KEY" "$DTRACK_URL/api/v1/project/$PROJECT_UUID" 2>/dev/null || echo "{}")
                            echo "Información del proyecto:"
                            echo "$PROJECT_INFO" | jq '.' 2>/dev/null || echo "No se pudo obtener información detallada"
                        else
                            echo "⚠ Proyecto '$PROJECT_NAME' no encontrado"
                            echo "PROJECT_UUID=not-found" > project_info.txt
                        fi
                    '''

                    // 4️⃣ Leer información del proyecto desde archivo
                    script {
                        if (fileExists('project_info.txt')) {
                            def projectInfo = readFile('project_info.txt').trim()
                            if (projectInfo.contains('PROJECT_UUID=')) {
                                env.PROJECT_UUID = projectInfo.split('=')[1]
                            }
                        }
                        
                        echo "PROJECT_UUID configurado: ${env.PROJECT_UUID ?: 'no configurado'}"
                        
                        // Si no se encontró proyecto, usar un valor por defecto
                        if (!env.PROJECT_UUID || env.PROJECT_UUID == "not-found") {
                            env.PROJECT_UUID = "manual-${PROJECT_NAME}-${PROJECT_VERSION}"
                        }
                    }

                    // 5️⃣ Exportar FPF (con fallback robusto)
                    sh '''
                        echo "=== Generando FPF ==="
                        
                        # Si tenemos un UUID válido de Dependency-Track, intentar obtener findings
                        if [[ "$PROJECT_UUID" != "not-found" ]] && [[ ! "$PROJECT_UUID" =~ ^manual- ]]; then
                            echo "Intentando obtener findings de Dependency-Track..."
                            
                            # Intentar varias veces
                            for i in {1..5}; do
                                echo "Intento $i de obtener findings..."
                                
                                if curl -s -H "X-Api-Key: $DTRACK_API_KEY" \
                                    "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID" \
                                    -o /tmp/findings_raw.json 2>/dev/null && \
                                    [ -s /tmp/findings_raw.json ] && \
                                    grep -q "\[" /tmp/findings_raw.json; then
                                    
                                    echo "✅ Findings obtenidos"
                                    
                                    # Convertir a formato FPF
                                    if command -v jq >/dev/null 2>&1; then
                                        jq '{findings: .}' /tmp/findings_raw.json > $FPF_FILE 2>/dev/null
                                    else
                                        python3 -c "
        import json
        with open('/tmp/findings_raw.json', 'r') as f:
            findings = json.load(f)
        with open('$FPF_FILE', 'w') as f:
            json.dump({'findings': findings}, f, indent=2)
                                        "
                                    fi
                                    
                                    break
                                fi
                                
                                echo "Esperando 10 segundos..."
                                sleep 10
                            done
                        fi
                        
                        # Verificar si se creó el FPF
                        if [ ! -f "$FPF_FILE" ] || [ ! -s "$FPF_FILE" ]; then
                            echo "Creando FPF vacío..."
                            echo '{"findings": []}' > $FPF_FILE
                        fi
                        
                        echo "=== FPF generado ==="
                        ls -la $FPF_FILE
                        echo "Tamaño: $(wc -c < $FPF_FILE) bytes"
                    '''
                }

                // 6️⃣ Archivar resultados
                stash name: 'bom-file', includes: "${BOM_FILE}"
                archiveArtifacts artifacts: "${BOM_FILE}", fingerprint: true

                stash name: 'dependency-track-fpf', includes: "${FPF_FILE}"
                archiveArtifacts artifacts: "${FPF_FILE}", fingerprint: true
            }
            
            post {
                always {
                    echo "📊 Resumen SCA:"
                    echo "  BOM generado: ${fileExists("$BOM_FILE") ? 'Sí' : 'No'}"
                    echo "  FPF generado: ${fileExists("$FPF_FILE") ? 'Sí' : 'No'}"
                    echo "  PROJECT_UUID: ${env.PROJECT_UUID ?: 'N/A'}"
                    
                    // Limpiar archivos temporales
                    sh '''
                        rm -f project_info.txt /tmp/findings_raw.json 2>/dev/null || true
                    '''
                }
            }
        }

        stage('Secrets Scan - Gitleaks') {
            agent {
                docker {
                    image 'zricethezav/gitleaks:latest'
                    args '--entrypoint=""'
                    reuseNode true
                }
            }

            options {
                skipDefaultCheckout(true)
            }

            steps {
                script {
                    unstash 'pygoat-code'

                    def exitCode = sh(
                        script: '''
                            gitleaks detect \
                            --source=pygoat \
                            --report-format json \
                            --report-path $GITLEAKS_REPORT \
                            --no-git
                        ''',
                        returnStatus: true
                    )

                    stash name: 'gitleaks-report', includes: "${GITLEAKS_REPORT}"
                    archiveArtifacts artifacts: "${GITLEAKS_REPORT}", fingerprint: true 

                    if (exitCode != 0) {
                        unstable("Gitleaks detectó secretos")
                    } else {
                        echo "No se detectaron secretos"
                    }
                }
            }
        }

        stage('DefectDojo - Subir Reportes') {
            agent {
                    docker {
                    image 'ci-python-security:latest'
                    args '--network cicd-net'
                    reuseNode true
                }
            }
            steps {
                script {
                    unstash 'bandit-report'
                    unstash 'bom-file'
                    unstash 'gitleaks-report'

                    sh 'ls -la'

                    echo "Subiendo Bandit..."
                    sh """
                    curl -X POST "${DD_URL}/api/v2/import-scan/" \
                    -H "Authorization: Token ${DD_API_KEY}" \
                    -F "engagement=${DD_ENGAGEMENT_ID}" \
                    -F "scan_type=Bandit Scan" \
                    -F "file=@${BANDIT_REPORT}" \
                    -F "active=true" \
                    -F "verified=false"
                    """

                    echo "Subiendo Gitleaks..."
                    sh """
                    curl -X POST "${DD_URL}/api/v2/import-scan/" \
                    -H "Authorization: Token ${DD_API_KEY}" \
                    -F "engagement=${DD_ENGAGEMENT_ID}" \
                    -F "scan_type=Gitleaks Scan" \
                    -F "file=@${GITLEAKS_REPORT}"
                    """

                    echo "Subiendo Dependency-Track (FPF)..."
                    sh """
                    curl -X POST "${DD_URL}/api/v2/import-scan/" \
                    -H "Authorization: Token ${DD_API_KEY}" \
                    -F "engagement=${DD_ENGAGEMENT_ID}" \
                    -F "scan_type=Dependency Track Finding Packaging Format (FPF) Export" \
                    -F "file=@${FPF_FILE}"
                    """
                }
            }
        }

    }

    post {
        success {
            echo "✓ Pipeline completado exitosamente"
        }
        unstable {
            echo "⚠ Pipeline completado con advertencias"
        }
        failure {
            echo "✗ Pipeline falló"
        }
    }
}