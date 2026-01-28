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

                    // 1️⃣ Generar SBOM - CORREGIDO
                    sh '''
                        cd pygoat
                        echo "Generando SBOM para requirements.txt..."
                        
                        # Verificar herramientas disponibles
                        echo "Herramientas disponibles:"
                        which cyclonedx-bom || echo "cyclonedx-bom no encontrado"
                        which cyclonedx-py || echo "cyclonedx-py no encontrado"
                        
                        # Usar cyclonedx-bom (recomendado) o cyclonedx-py sin --format
                        if command -v cyclonedx-bom &> /dev/null; then
                            echo "Usando cyclonedx-bom..."
                            cyclonedx-bom -r requirements.txt -o ../$BOM_FILE
                        elif command -v cyclonedx-py &> /dev/null; then
                            echo "Usando cyclonedx-py..."
                            cyclonedx-py requirements requirements.txt -o ../$BOM_FILE
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
                        echo "Contenido del BOM (primeras 1000 caracteres):"
                        head -c 1000 ../$BOM_FILE
                        echo ""
                    '''

                    // 2️⃣ Verificar conexión con Dependency-Track
                    sh '''
                        echo "=== Verificando conexión con Dependency-Track ==="
                        echo "URL: $DTRACK_URL"
                        echo "API Key: ${#DTRACK_API_KEY} caracteres"
                        
                        # Probar conexión básica
                        curl -s -H "X-Api-Key: $DTRACK_API_KEY" "$DTRACK_URL/api/version" || echo "⚠ No se pudo conectar a Dependency-Track"
                        echo ""
                    '''

                    // 3️⃣ Subir SBOM - IMPORTANTE: Versión correcta de la API
                    sh '''
                        echo "=== Subiendo BOM a Dependency-Track ==="
                        echo "Proyecto: $PROJECT_NAME"
                        echo "Versión: $PROJECT_VERSION"
                        
                        # IMPORTANTE: Dependency-Track v4.x usa projectName y projectVersion
                        # v3.x usaba project y version
                        RESPONSE=$(curl -s -w "\\n%{http_code}" -X POST "$DTRACK_URL/api/v1/bom" \
                            -H "X-Api-Key: $DTRACK_API_KEY" \
                            -F "projectName=$PROJECT_NAME" \
                            -F "projectVersion=$PROJECT_VERSION" \
                            -F "autoCreate=true" \
                            -F "bom=@$BOM_FILE" \
                            -F "parentUUID=" \
                            -F "parentName=")
                        
                        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
                        RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')
                        
                        echo "Código HTTP: $HTTP_CODE"
                        echo "Respuesta: $RESPONSE_BODY"
                        
                        if [[ "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
                            echo "✅ BOM subido exitosamente"
                        else
                            echo "⚠ Error al subir BOM. Código: $HTTP_CODE"
                            echo "Intentando con formato alternativo..."
                            
                            # Intentar con formato alternativo para versiones antiguas
                            ALT_RESPONSE=$(curl -s -w "\\n%{http_code}" -X POST "$DTRACK_URL/api/v1/bom" \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                -F "project=$PROJECT_NAME" \
                                -F "version=$PROJECT_VERSION" \
                                -F "autoCreate=true" \
                                -F "bom=@$BOM_FILE")
                            
                            ALT_HTTP_CODE=$(echo "$ALT_RESPONSE" | tail -n1)
                            ALT_BODY=$(echo "$ALT_RESPONSE" | sed '$d')
                            
                            echo "Código HTTP (alternativo): $ALT_HTTP_CODE"
                            echo "Respuesta (alternativa): $ALT_BODY"
                            
                            if [[ ! "$ALT_HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
                                echo "❌ Ambos intentos fallaron"
                            fi
                        fi
                    '''

                    // 4️⃣ Función auxiliar para esperar versión
                    sh '''#!/bin/bash
                        wait_for_version() {
                            local project_name="$1"
                            local version_name="$2"
                            local max_attempts="${3:-20}"
                            local wait_seconds="${4:-10}"
                            
                            echo "Buscando proyecto: $project_name, versión: $version_name"
                            
                            # Buscar proyecto
                            local project_uuid=""
                            for ((i=1; i<=max_attempts; i++)); do
                                echo "Intento $i - Buscando proyecto..."
                                
                                local projects_json=$(curl -s -H "X-Api-Key: $DTRACK_API_KEY" \
                                    "$DTRACK_URL/api/v1/project")
                                
                                project_uuid=$(echo "$projects_json" | jq -r --arg name "$project_name" \
                                    '.[] | select(.name == $name) | .uuid')
                                
                                if [ -n "$project_uuid" ] && [ "$project_uuid" != "null" ]; then
                                    echo "✅ Proyecto encontrado: $project_uuid"
                                    break
                                fi
                                
                                if [ $i -eq $max_attempts ]; then
                                    echo "❌ Proyecto no encontrado después de $max_attempts intentos"
                                    return 1
                                fi
                                
                                sleep $wait_seconds
                            done
                            
                            # Buscar versión específica
                            local version_uuid=""
                            for ((i=1; i<=max_attempts; i++)); do
                                echo "Intento $i - Buscando versión '$version_name'..."
                                
                                local versions_json=$(curl -s -H "X-Api-Key: $DTRACK_API_KEY" \
                                    "$DTRACK_URL/api/v1/project/$project_uuid")
                                
                                echo "Información del proyecto:"
                                echo "$versions_json" | jq '.'
                                
                                # Extraer versiones del proyecto
                                version_uuid=$(echo "$versions_json" | jq -r --arg version "$version_name" \
                                    '.versions[]? | select(.version == $version) | .uuid')
                                
                                if [ -n "$version_uuid" ] && [ "$version_uuid" != "null" ]; then
                                    echo "✅ Versión encontrada: $version_uuid"
                                    echo "VERSION_UUID=$version_uuid"
                                    return 0
                                fi
                                
                                # Intentar con otro formato de respuesta
                                version_uuid=$(echo "$versions_json" | jq -r --arg version "$version_name" \
                                    '.version // empty')
                                
                                if [ -n "$version_uuid" ] && [ "$version_uuid" != "null" ]; then
                                    echo "✅ Versión encontrada (formato alternativo): $version_uuid"
                                    echo "VERSION_UUID=$version_uuid"
                                    return 0
                                fi
                                
                                echo "Versión no encontrada, esperando $wait_seconds segundos..."
                                sleep $wait_seconds
                            done
                            
                            echo "⚠ Versión '$version_name' no encontrada"
                            echo "Usando UUID del proyecto como versión: $project_uuid"
                            echo "VERSION_UUID=$project_uuid"
                            return 0
                        }
                        
                        # Ejecutar la función
                        wait_for_version "$PROJECT_NAME" "$PROJECT_VERSION" 20 10
                    '''

                    // 5️⃣ Usar variables de entorno para almacenar UUIDs
                    script {
                        // Extraer VERSION_UUID del output anterior
                        env.PROJECT_UUID = sh(
                            script: '''
                                curl -s -H "X-Api-Key: $DTRACK_API_KEY" "$DTRACK_URL/api/v1/project" | \
                                jq -r --arg name "$PROJECT_NAME" '.[] | select(.name == $name) | .uuid'
                            ''',
                            returnStdout: true
                        ).trim()
                        
                        echo "PROJECT_UUID extraído: ${env.PROJECT_UUID}"
                        
                        if (env.PROJECT_UUID == "null" || env.PROJECT_UUID == "") {
                            echo "⚠ No se pudo obtener PROJECT_UUID, continuando sin Dependency-Track"
                            env.PROJECT_UUID = "not-found"
                            env.VERSION_UUID = "not-found"
                        } else {
                            // Intentar obtener VERSION_UUID
                            env.VERSION_UUID = sh(
                                script: '''
                                    curl -s -H "X-Api-Key: $DTRACK_API_KEY" "$DTRACK_URL/api/v1/project/${PROJECT_UUID}" | \
                                    jq -r --arg version "$PROJECT_VERSION" '.versions[]? | select(.version == $version) | .uuid // .uuid // empty'
                                ''',
                                returnStdout: true
                            ).trim()
                            
                            if (env.VERSION_UUID == "null" || env.VERSION_UUID == "") {
                                echo "⚠ No se pudo obtener VERSION_UUID específica, usando PROJECT_UUID"
                                env.VERSION_UUID = env.PROJECT_UUID
                            }
                            
                            echo "VERSION_UUID: ${env.VERSION_UUID}"
                        }
                    }

                    // 6️⃣ Exportar FPF - Versión simplificada
                    sh '''
                        echo "=== Exportando resultados de Dependency-Track ==="
                        
                        if [ "$PROJECT_UUID" = "not-found" ]; then
                            echo "⚠ Proyecto no encontrado, creando FPF vacío"
                            echo '{"findings": []}' > $FPF_FILE
                        else
                            echo "Usando PROJECT_UUID: $PROJECT_UUID"
                            
                            # Intentar exportar findings en formato FPF
                            if curl -s -H "X-Api-Key: $DTRACK_API_KEY" \
                                "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID/export" \
                                -o $FPF_FILE 2>/dev/null; then
                                
                                echo "✅ FPF exportado exitosamente"
                                
                            # Si falla, intentar obtener findings en formato JSON
                            elif curl -s -H "X-Api-Key: $DTRACK_API_KEY" \
                                "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID" \
                                -o /tmp/findings.json 2>/dev/null; then
                                
                                echo "Convirtiendo findings a formato FPF..."
                                
                                # Convertir a formato FPF básico
                                if [ -s /tmp/findings.json ]; then
                                    jq '{findings: .}' /tmp/findings.json > $FPF_FILE 2>/dev/null || \
                                    echo '{"findings": []}' > $FPF_FILE
                                else
                                    echo '{"findings": []}' > $FPF_FILE
                                fi
                                
                            else
                                echo "⚠ No se pudieron obtener findings, creando FPF vacío"
                                echo '{"findings": []}' > $FPF_FILE
                            fi
                        fi
                        
                        echo "Archivo FPF creado:"
                        ls -la $FPF_FILE
                        echo "Tamaño: $(wc -c < $FPF_FILE) bytes"
                    '''
                }

                // 7️⃣ Archivar resultados
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
                    echo "⚠ Stage SCA - Dependency-Track encontró problemas"
                    script {
                        // Crear archivos vacíos para permitir que el pipeline continúe
                        sh '''
                            echo '{"findings": []}' > $FPF_FILE 2>/dev/null || true
                            echo '{"bomFormat": "CycloneDX", "version": 1}' > $BOM_FILE 2>/dev/null || true
                        '''
                        stash name: 'bom-file', includes: "${BOM_FILE}"
                        stash name: 'dependency-track-fpf', includes: "${FPF_FILE}"
                    }
                }
                always {
                    echo "📊 Dependency-Track: Proyecto ${PROJECT_NAME}:${PROJECT_VERSION}"
                    echo "   PROJECT_UUID: ${env.PROJECT_UUID ?: 'No encontrado'}"
                    echo "   VERSION_UUID: ${env.VERSION_UUID ?: 'No encontrado'}"
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