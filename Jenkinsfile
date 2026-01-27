pipeline {
    agent any

    environment {

        HOME = "${WORKSPACE}"

        //Bandit 
        BANDIT_REPORT = 'reporte_bandit.json'

        //Dependency Track
        DTRACK_URL = 'http://dtrack-api:8080'
        DTRACK_API_KEY = credentials('dependency-track-api-key')
        PROJECT_NAME = 'pygoat'
        PROJECT_VERSION = "ejercicio-2"
        BOM_FILE = 'bom.json'
        FPF_FILE = 'fpf.json'
        
        // Gitleaks
        GITLEAKS_REPORT = 'gitleaks-report.json'

        // Defect Dojo
        DD_URL = 'http://django-defectdojo-nginx-1:8080'
        DD_API_KEY = credentials('defectdojo-api-key')
        DD_PRODUCT_NAME = 'pygoat'
        DD_ENGAGEMENT_NAME = 'Jenkins Pipeline - Ejercicio 2'
        DD_ENGAGEMENT_ID = '2'
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
            environment {
                // Añade estas variables
                DTRACK_TIMEOUT = '300'  // 5 minutos máximo de espera
                DTRACK_INTERVAL = '10'  // Verificar cada 10 segundos
            }
            steps {
                script {
                    unstash 'pygoat-code'

                    // 1. Generar SBOM
                    sh '''
                        cd pygoat
                        cyclonedx-py requirements requirements.txt -o ../$BOM_FILE --no-validate
                    '''

                    // 2. Subir SBOM a Dependency-Track
                    echo "Subiendo SBOM a Dependency-Track..."
                    def uploadExitCode = sh(script: '''
                        curl -s -w "%{http_code}" -X POST "$DTRACK_URL/api/v1/bom" \
                        -H "X-Api-Key: $DTRACK_API_KEY" \
                        -F "projectName=$PROJECT_NAME" \
                        -F "projectVersion=$PROJECT_VERSION" \
                        -F "autoCreate=true" \
                        -F "bom=@$BOM_FILE"
                    ''', returnStatus: true)
                    
                    if (uploadExitCode != 0 && uploadExitCode != 200 && uploadExitCode != 201) {
                        echo "⚠️  Código de respuesta: ${uploadExitCode}"
                        unstable(message: "Posible problema al subir SBOM a Dependency-Track")
                    } else {
                        echo "✅ BOM subido a Dependency-Track. Esperando análisis..."
                        
                        // 3. Esperar a que el análisis se complete
                        def projectUuid = ''
                        def attempts = DTRACK_TIMEOUT.toInteger() / DTRACK_INTERVAL.toInteger()
                        def analyzed = false
                        
                        for (int i = 0; i < attempts; i++) {
                            sleep(DTRACK_INTERVAL.toInteger())
                            
                            // Obtener el UUID del proyecto
                            sh '''
                                curl -s -X GET "$DTRACK_URL/api/v1/project/lookup?name=$PROJECT_NAME&version=$PROJECT_VERSION" \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                -o project-info.json
                            '''
                            
                            // Verificar si el proyecto existe y tiene UUID
                            if (fileExists('project-info.json')) {
                                def projectInfo = readJSON file: 'project-info.json'
                                if (projectInfo && projectInfo.uuid) {
                                    projectUuid = projectInfo.uuid
                                    echo "✅ Proyecto encontrado. UUID: ${projectUuid}"
                                    
                                    // Verificar métricas para ver si el análisis está completo
                                    sh """
                                        curl -s -X GET "$DTRACK_URL/api/v1/metrics/project/${projectUuid}/current" \
                                        -H "X-Api-Key: $DTRACK_API_KEY" \
                                        -o metrics.json
                                    """
                                    
                                    if (fileExists('metrics.json')) {
                                        def metrics = readJSON file: 'metrics.json'
                                        if (metrics) {
                                            echo "📊 Métricas: Vulnerabilidades=${metrics.vulnerabilities?.total ?: 0}, Dependencias=${metrics.components?.total ?: 0}"
                                            analyzed = true
                                            break
                                        }
                                    }
                                }
                            }
                            
                            echo "⏳ Esperando análisis de Dependency-Track... (${(i+1) * DTRACK_INTERVAL.toInteger()}s/${DTRACK_TIMEOUT}s)")
                        }
                        
                        if (analyzed && projectUuid) {
                            // 4. Exportar reporte FPF (Finding Packaging Format)
                            echo "📦 Exportando reporte FPF desde Dependency-Track..."
                            sh """
                                curl -s -X GET "$DTRACK_URL/api/v1/finding/project/${projectUuid}/export?format=JSON" \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                -o $FPF_FILE
                            """
                            
                            // Verificar que el archivo FPF se creó y no está vacío
                            if (fileExists("${FPF_FILE}")) {
                                def fileSize = sh(script: "wc -c < ${FPF_FILE}", returnStdout: true).trim().toInteger()
                                if (fileSize > 100) {  // Más de 100 bytes
                                    echo "✅ Reporte FPF generado: ${fileSize} bytes"
                                    stash name: 'fpf-file', includes: "${FPF_FILE}"
                                } else {
                                    echo "⚠️  El reporte FPF está vacío o es muy pequeño"
                                }
                            } else {
                                echo "❌ No se pudo generar el reporte FPF"
                            }
                            
                            // 5. También podemos exportar el BOM con vulnerabilidades
                            echo "📦 Exportando BOM con vulnerabilidades..."
                            sh """
                                curl -s -X GET "$DTRACK_URL/api/v1/bom/cyclonedx/project/${projectUuid}" \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                -o bom-with-vulns.json
                            """
                            
                            if (fileExists('bom-with-vulns.json')) {
                                stash name: 'bom-with-vulns', includes: 'bom-with-vulns.json'
                            }
                            
                        } else {
                            echo "❌ El análisis de Dependency-Track no se completó en el tiempo esperado"
                        }
                    }
                    
                    // Archivar resultados
                    stash name: 'bom-file', includes: "${BOM_FILE}"
                    archiveArtifacts artifacts: "${BOM_FILE}", fingerprint: true
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
                    
                    // IMPORTANTE: Usar el archivo FPF, no el BOM
                    if (fileExists("${WORKSPACE}/${FPF_FILE}")) {
                        unstash 'fpf-file'
                        echo "✅ Usando reporte FPF para Dependency Track"
                    } else {
                        echo "⚠️  No hay reporte FPF, usando BOM básico"
                    }

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

                    echo "Subiendo Dependency-Track..."
                    if (fileExists("${FPF_FILE}")) {
                        // Usar el FPF (con vulnerabilidades)
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