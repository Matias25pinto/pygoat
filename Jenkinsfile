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
                    git checkout ejercicio-2
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
                    sh "rm -f ${BANDIT_REPORT} || true"
                    
                    // Ejecutar Bandit capturando el exit code
                    def banditExitCode = sh(script: '''
                        cd pygoat
                        bandit -r . -f json -o ../$BANDIT_REPORT
                    ''', returnStatus: true, env: ['BANDIT_REPORT': BANDIT_REPORT])
                    
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
                    sh "test -f ${BANDIT_REPORT} && echo 'Archivo ${BANDIT_REPORT} creado' || echo 'Archivo no existe, creando vacío...'"
                    sh "test -f ${BANDIT_REPORT} || echo '{}' > ${BANDIT_REPORT}"
                    sh "ls -la ${BANDIT_REPORT}"
                }
                // Archivar resultados
                archiveArtifacts artifacts: "${BANDIT_REPORT}", fingerprint: true, allowEmptyArchive: true
            }
            
            post {
                always {
                    script {
                        if (fileExists(BANDIT_REPORT)) {
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

                    // Generar SBOM desde requirements.txt
                    sh """
                        cd pygoat
                        cyclonedx-py requirements requirements.txt -o ../${BOM_FILE}
                    """

                    // Subir SBOM a Dependency-Track
                    def uploadExitCode = sh(script: '''
                        curl -s -X POST "$DTRACK_URL/api/v1/bom" \
                        -H "X-Api-Key: $DTRACK_API_KEY" \
                        -F "projectName=$PROJECT_NAME" \
                        -F "projectVersion=$PROJECT_VERSION" \
                        -F "autoCreate=true" \
                        -F "bom=@$BOM_FILE"
                    ''', returnStatus: true, env: ['BOM_FILE': BOM_FILE])
                    
                    echo "Curl exit code: ${uploadExitCode}"
                    
                    if (uploadExitCode != 0) {
                        unstable(message: "No se pudo subir SBOM a Dependency-Track")
                        echo "Dependency-Track podría no estar disponible"
                    }
                }

                // Archivar resultados
                archiveArtifacts artifacts: "${BOM_FILE}", fingerprint: true, allowEmptyArchive: true
            }

            post {
                always {
                    script {
                        if (fileExists(BOM_FILE)) {
                            echo "Resultados de Dependency-Track disponibles para análisis"
                        }
                    }
                }
            }
        }

        stage('Security Gate - Dependency-Track') {
            agent {
                docker {
                    image 'ci-python-security:latest'
                    args '--network cicd-net'
                    reuseNode true
                }
            }
            steps {
                script {
                    sleep(time: 30, unit: 'SECONDS')
                    
                    withCredentials([string(credentialsId: 'dependency-track-api-key', variable: 'DTRACK_API_KEY')]) {
                        // 1. Crear script shell seguro
                        writeFile file: 'get_metrics.sh', text: '''#!/bin/bash
                            # Obtener proyecto
                            PROJECT_INFO=$(curl -s -X GET "$DTRACK_URL/api/v1/project/lookup?name=$PROJECT_NAME&version=$PROJECT_VERSION" \
                                -H "X-Api-Key: $DTRACK_API_KEY")
                            
                            # Extraer UUID
                            PROJECT_UUID=$(echo "$PROJECT_INFO" | jq -r '.uuid')
                            
                            # Obtener métricas
                            METRICS=$(curl -s -X GET "$DTRACK_URL/api/v1/metrics/project/$PROJECT_UUID/current" \
                                -H "X-Api-Key: $DTRACK_API_KEY")
                            
                            # Extraer valores
                            CRITICAL=$(echo "$METRICS" | jq '.critical // 0')
                            HIGH=$(echo "$METRICS" | jq '.high // 0')
                            
                            echo "CRITICAL=$CRITICAL"
                            echo "HIGH=$HIGH"
                        '''
                        
                        sh 'chmod +x get_metrics.sh && ./get_metrics.sh > metrics_output.txt'
                        
                        // 2. Leer resultados
                        def output = readFile('metrics_output.txt').trim()
                        def critical = 0
                        def high = 0
                        
                        output.eachLine { line ->
                            if (line.startsWith('CRITICAL=')) {
                                critical = line.replace('CRITICAL=', '').toInteger()
                            } else if (line.startsWith('HIGH=')) {
                                high = line.replace('HIGH=', '').toInteger()
                            }
                        }
                        
                        echo "Métricas Dependency-Track:"
                        echo "  - Críticas: ${critical}"
                        echo "  - Altas: ${high}"
                        
                        if (critical > 0 || high > 0) {
                            error("SECURITY GATE FALLIDO: Dependency-Track reportó ${critical} críticas y ${high} altas")
                        } else {
                            echo "Security Gate: No hay vulnerabilidades críticas/altas en dependencias"
                        }
                    }
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
                        returnStatus: true, env: ['GITLEAKS_REPORT': GITLEAKS_REPORT]
                    )

                    archiveArtifacts artifacts: "${GITLEAKS_REPORT}",
                                    fingerprint: true,
                                    allowEmptyArchive: true

                    if (exitCode != 0) {
                        unstable("Gitleaks detectó secretos")
                    } else {
                        echo "No se detectaron secretos"
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