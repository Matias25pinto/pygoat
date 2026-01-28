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

                    // 1️⃣ Generar SBOM
                    sh '''
                        cd pygoat
                        cyclonedx-py requirements requirements.txt -o ../$BOM_FILE --no-validate
                    '''

                    // 2️⃣ Subir SBOM a Dependency-Track
                    sh '''
                        curl -s -X POST "$DTRACK_URL/api/v1/bom" \
                        -H "X-Api-Key: $DTRACK_API_KEY" \
                        -F "projectName=$PROJECT_NAME" \
                        -F "projectVersion=$PROJECT_VERSION" \
                        -F "autoCreate=true" \
                        -F "bom=@$BOM_FILE"
                    '''

                    // 3️⃣ Obtener PROJECT_UUID y esperar VERSION_UUID
                    sh '''#!/bin/bash
                        set -e
                        
                        PROJECT_UUID=$(curl -s \
                        -H "X-Api-Key: $DTRACK_API_KEY" \
                        "$DTRACK_URL/api/v1/project?name=$PROJECT_NAME" | jq -r '.[0].uuid')

                        echo "PROJECT_UUID=$PROJECT_UUID"

                        if [ -z "$PROJECT_UUID" ]; then
                            echo "❌ No se pudo obtener PROJECT_UUID"
                            exit 1
                        fi

                        echo "⏳ Esperando a que la versión '$PROJECT_VERSION' exista..."

                        MAX_ATTEMPTS=12
                        VERSION_UUID=""
                        
                        for ((i=1; i<=MAX_ATTEMPTS; i++)); do
                            VERSION_UUID=$(curl -s \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                "$DTRACK_URL/api/v1/project/$PROJECT_UUID/versions" \
                                | jq -r --arg VERSION "$PROJECT_VERSION" \
                                '.[] | select(.version == $VERSION) | .uuid')

                            echo "Intento $i - VERSION_UUID=$VERSION_UUID"

                            if [ -n "$VERSION_UUID" ]; then
                                echo "✅ Versión encontrada"
                                break
                            fi

                            if [ $i -eq $MAX_ATTEMPTS ]; then
                                echo "❌ La versión nunca fue creada después de $MAX_ATTEMPTS intentos"
                                exit 1
                            fi
                            
                            sleep 10
                        done

                        if [ -z "$VERSION_UUID" ]; then
                            echo "❌ La versión nunca fue creada"
                            exit 1
                        fi
                    '''

                    // 4️⃣ Esperar findings - también usar bash
                    sh '''#!/bin/bash
                        echo "Esperando a que Dependency-Track genere findings..."

                        MAX_ATTEMPTS=12
                        FINDINGS_COUNT=0
                        
                        for ((i=1; i<=MAX_ATTEMPTS; i++)); do
                            FINDINGS_COUNT=$(curl -s \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID/version/$VERSION_UUID" \
                                | jq 'length')

                            echo "Intento $i - Findings: $FINDINGS_COUNT"

                            if [ "$FINDINGS_COUNT" -gt 0 ]; then
                                echo "✅ Findings generados"
                                break
                            fi

                            if [ $i -eq $MAX_ATTEMPTS ]; then
                                echo "⚠ No se encontraron findings después de $MAX_ATTEMPTS intentos"
                                echo "⚠ Continuando de todos modos..."
                            fi
                            
                            sleep 15
                        done
                    '''

                    // 5️⃣ Exportar FPF
                    sh '''
                        curl -s \
                        -H "X-Api-Key: $DTRACK_API_KEY" \
                        "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID/version/$VERSION_UUID/fpf" \
                        -o $FPF_FILE

                        if [ ! -s "$FPF_FILE" ]; then
                            echo "⚠ FPF generado pero vacío"
                            # Crear un FPF vacío válido si está vacío
                            echo '{"findings": []}' > $FPF_FILE
                        else
                            echo "✅ FPF generado correctamente"
                        fi
                    '''
                }

                // 6️⃣ Archivos para siguientes stages
                stash name: 'bom-file', includes: "${BOM_FILE}"
                archiveArtifacts artifacts: "${BOM_FILE}", fingerprint: true

                stash name: 'dependency-track-fpf', includes: "${FPF_FILE}"
                archiveArtifacts artifacts: "${FPF_FILE}", fingerprint: true
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