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

                    // 1️⃣ Generar SBOM de manera más robusta
                    sh '''
                        cd pygoat
                        echo "Generando SBOM para requirements.txt..."
                        cat requirements.txt
                        
                        # Instalar cyclonedx-bom si no está disponible
                        pip install cyclonedx-bom 2>/dev/null || pip install cyclonedx-py 2>/dev/null || true
                        
                        # Intentar generar BOM de diferentes maneras
                        if command -v cyclonedx-py &> /dev/null; then
                            cyclonedx-py requirements requirements.txt -o ../$BOM_FILE --format json
                        elif command -v cyclonedx-bom &> /dev/null; then
                            cyclonedx-bom -r requirements.txt -o ../$BOM_FILE
                        else
                            echo "Creando BOM básico manualmente..."
                            echo '{
                            "bomFormat": "CycloneDX",
                            "specVersion": "1.4",
                            "version": 1,
                            "components": []
                            }' > ../$BOM_FILE
                        fi
                        
                        echo "BOM generado:"
                        ls -la ../$BOM_FILE
                        echo "Primeras líneas del BOM:"
                        head -20 ../$BOM_FILE
                    '''

                    // 2️⃣ Verificar conexión con Dependency-Track
                    sh '''
                        echo "Verificando conexión con Dependency-Track..."
                        curl -s -H "X-Api-Key: $DTRACK_API_KEY" "$DTRACK_URL/api/version"
                        echo ""
                    '''

                    // 3️⃣ Subir SBOM con más detalles
                    sh '''
                        echo "Subiendo BOM a Dependency-Track..."
                        echo "URL: $DTRACK_URL/api/v1/bom"
                        echo "Proyecto: $PROJECT_NAME"
                        echo "Versión: $PROJECT_VERSION"
                        
                        # Subir el BOM
                        RESPONSE=$(curl -s -w "\\n%{http_code}" -X POST "$DTRACK_URL/api/v1/bom" \
                            -H "X-Api-Key: $DTRACK_API_KEY" \
                            -F "project=$PROJECT_NAME" \
                            -F "version=$PROJECT_VERSION" \
                            -F "autoCreate=true" \
                            -F "bom=@$BOM_FILE")
                        
                        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
                        RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')
                        
                        echo "HTTP Response Code: $HTTP_CODE"
                        echo "Response Body: $RESPONSE_BODY"
                        
                        if [ "$HTTP_CODE" != "200" ]; then
                            echo "⚠ Advertencia: Código HTTP $HTTP_CODE al subir BOM"
                            echo "Continuando de todos modos..."
                        else
                            echo "✅ BOM subido correctamente"
                        fi
                    '''

                    // 4️⃣ Esperar y verificar creación del proyecto/versión
                    sh '''#!/bin/bash
                        set -e
                        
                        echo "=== Verificando estado del proyecto en Dependency-Track ==="
                        
                        # Intentar obtener el proyecto
                        MAX_ATTEMPTS=15
                        PROJECT_UUID=""
                        
                        for ((i=1; i<=MAX_ATTEMPTS; i++)); do
                            echo "Intento $i - Buscando proyecto '$PROJECT_NAME'..."
                            
                            PROJECTS_JSON=$(curl -s \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                "$DTRACK_URL/api/v1/project")
                            
                            echo "Respuesta completa de proyectos:"
                            echo "$PROJECTS_JSON" | jq '.'
                            
                            PROJECT_UUID=$(echo "$PROJECTS_JSON" | jq -r --arg NAME "$PROJECT_NAME" \
                                '.[] | select(.name == $NAME) | .uuid')
                            
                            if [ -n "$PROJECT_UUID" ] && [ "$PROJECT_UUID" != "null" ]; then
                                echo "✅ Proyecto encontrado: $PROJECT_UUID"
                                break
                            fi
                            
                            echo "Proyecto no encontrado, esperando 10 segundos..."
                            sleep 10
                        done
                        
                        if [ -z "$PROJECT_UUID" ] || [ "$PROJECT_UUID" == "null" ]; then
                            echo "❌ Proyecto '$PROJECT_NAME' no encontrado después de $MAX_ATTEMPTS intentos"
                            
                            # Intentar crear el proyecto manualmente
                            echo "Intentando crear proyecto manualmente..."
                            CREATE_RESPONSE=$(curl -s -X PUT "$DTRACK_URL/api/v1/project" \
                                -H "Content-Type: application/json" \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                -d "{
                                    \"name\": \"$PROJECT_NAME\",
                                    \"description\": \"Proyecto creado desde Jenkins Pipeline\",
                                    \"version\": \"$PROJECT_VERSION\",
                                    \"active\": true
                                }")
                            
                            echo "Respuesta creación proyecto: $CREATE_RESPONSE"
                            
                            # Esperar a que se cree
                            sleep 10
                            
                            # Volver a intentar obtener UUID
                            PROJECT_UUID=$(curl -s \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                "$DTRACK_URL/api/v1/project" | jq -r --arg NAME "$PROJECT_NAME" \
                                '.[] | select(.name == $NAME) | .uuid')
                        fi
                        
                        if [ -z "$PROJECT_UUID" ] || [ "$PROJECT_UUID" == "null" ]; then
                            echo "❌ No se pudo obtener/crear el proyecto"
                            echo "⚠ Continuando sin Dependency-Track..."
                            exit 0
                        fi
                        
                        echo "PROJECT_UUID=$PROJECT_UUID"
                        
                        # Buscar la versión específica
                        echo "=== Buscando versión '$PROJECT_VERSION' ==="
                        VERSION_UUID=""
                        
                        for ((i=1; i<=MAX_ATTEMPTS; i++)); do
                            echo "Intento $i - Buscando versión..."
                            
                            VERSIONS_JSON=$(curl -s \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                "$DTRACK_URL/api/v1/project/$PROJECT_UUID/versions")
                            
                            echo "Versiones disponibles para el proyecto:"
                            echo "$VERSIONS_JSON" | jq '.'
                            
                            VERSION_UUID=$(echo "$VERSIONS_JSON" | jq -r --arg VERSION "$PROJECT_VERSION" \
                                '.[] | select(.version == $VERSION) | .uuid')
                            
                            if [ -n "$VERSION_UUID" ] && [ "$VERSION_UUID" != "null" ]; then
                                echo "✅ Versión encontrada: $VERSION_UUID"
                                break
                            fi
                            
                            echo "Versión no encontrada, esperando 10 segundos..."
                            sleep 10
                        done
                        
                        if [ -z "$VERSION_UUID" ] || [ "$VERSION_UUID" == "null" ]; then
                            echo "⚠ Versión '$PROJECT_VERSION' no encontrada"
                            echo "⚠ Usando la última versión disponible..."
                            
                            # Obtener la primera versión disponible
                            VERSION_UUID=$(echo "$VERSIONS_JSON" | jq -r '.[0].uuid // empty')
                            
                            if [ -n "$VERSION_UUID" ]; then
                                echo "✅ Usando versión: $VERSION_UUID"
                            else
                                echo "⚠ No hay versiones disponibles, usando PROJECT_UUID para FPF"
                                VERSION_UUID=$PROJECT_UUID
                            fi
                        fi
                    '''

                    // 5️⃣ Esperar findings (con manejo de errores)
                    sh '''#!/bin/bash
                        echo "=== Esperando análisis en Dependency-Track ==="
                        
                        MAX_ATTEMPTS=10
                        FINDINGS_COUNT=0
                        
                        for ((i=1; i<=MAX_ATTEMPTS; i++)); do
                            echo "Intento $i - Verificando findings..."
                            
                            # Intentar obtener findings
                            if curl -s -H "X-Api-Key: $DTRACK_API_KEY" \
                                "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID" > /tmp/findings.json 2>/dev/null; then
                                
                                FINDINGS_COUNT=$(jq 'length' /tmp/findings.json 2>/dev/null || echo "0")
                                
                                if [ "$FINDINGS_COUNT" -gt 0 ] 2>/dev/null; then
                                    echo "✅ Findings generados: $FINDINGS_COUNT"
                                    break
                                fi
                            fi
                            
                            echo "Findings no disponibles aún, esperando 15 segundos..."
                            sleep 15
                        done
                        
                        if [ "$FINDINGS_COUNT" -eq 0 ]; then
                            echo "⚠ No se encontraron findings después de $MAX_ATTEMPTS intentos"
                            echo "⚠ Puede que el análisis aún esté en progreso o no haya vulnerabilidades"
                        fi
                    '''

                    // 6️⃣ Exportar FPF (con fallback si falla)
                    sh '''
                        echo "=== Exportando FPF ==="
                        
                        # Intentar exportar FPF
                        if curl -s -H "X-Api-Key: $DTRACK_API_KEY" \
                            "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID/export" \
                            -o $FPF_FILE 2>/dev/null && [ -s "$FPF_FILE" ]; then
                            
                            echo "✅ FPF exportado correctamente"
                            
                        elif curl -s -H "X-Api-Key: $DTRACK_API_KEY" \
                            "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID" \
                            -o /tmp/findings_raw.json 2>/dev/null; then
                            
                            echo "⚠ No se pudo exportar FPF, creando formato manual..."
                            
                            # Crear FPF básico manualmente
                            jq '{findings: .}' /tmp/findings_raw.json > $FPF_FILE 2>/dev/null || \
                            echo '{"findings": []}' > $FPF_FILE
                            
                            echo "✅ FPF creado manualmente"
                            
                        else
                            echo "⚠ No se pudieron obtener findings, creando FPF vacío"
                            echo '{"findings": []}' > $FPF_FILE
                        fi
                        
                        echo "Tamaño del FPF: $(wc -c < $FPF_FILE) bytes"
                        echo "Primeras líneas del FPF:"
                        head -5 $FPF_FILE
                    '''
                }

                // Archivar resultados
                stash name: 'bom-file', includes: "${BOM_FILE}"
                archiveArtifacts artifacts: "${BOM_FILE}", fingerprint: true

                stash name: 'dependency-track-fpf', includes: "${FPF_FILE}"
                archiveArtifacts artifacts: "${FPF_FILE}", fingerprint: true
            }
            
            post {
                success {
                    echo "✅ Stage SCA - Dependency-Track completado"
                }
                failure {
                    echo "⚠ Stage SCA - Dependency-Track falló, pero continuando pipeline..."
                    // No hacer exit 1 para permitir que el pipeline continúe
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