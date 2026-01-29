pipeline {
    agent any

    environment {

        // Defect Dojo
        DD_URL = 'http://django-defectdojo-nginx-1:8080'
        DD_API_KEY = credentials('defectdojo-api-key')
        DD_ENGAGEMENT_ID = '4'
        
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
                    
                    //capturar si encontro vulnerabilidades retorna 1
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
                    
                    def SCAN_DATE = sh(script: "date -u +%Y-%m-%dT%H:%M:%SZ", returnStdout: true).trim()

                    echo "Subiendo Bandit..."
                    sh(
                        script: '''
                            curl -X POST "${DD_URL}/api/v2/import-scan/" \
                            -H "Authorization: Token $DD_API_KEY" \
                            -F "engagement=$DD_ENGAGEMENT_ID" \
                            -F "scan_type=Bandit Scan" \
                            -F "scan_date=$SCAN_DATE" \
                            -F "file=@$BANDIT_REPORT" \
                            -F "active=true" \
                            -F "verified=true"
                        ''',
                        returnStatus: true, env: ['DD_API_KEY': DD_API_KEY, 'DD_ENGAGEMENT_ID': DD_ENGAGEMENT_ID, 'SCAN_DATE': SCAN_DATE, 'BANDIT_REPORT': BANDIT_REPORT]
                    )

                    echo "Subiendo Gitleaks..."
                    sh(
                        script: '''
                            curl -X POST "${DD_URL}/api/v2/import-scan/" \
                            -H "Authorization: Token $DD_API_KEY" \
                            -F "engagement=$DD_ENGAGEMENT_ID" \
                            -F "scan_type=Gitleaks Scan" \
                            -F "scan_date=$SCAN_DATE" \
                            -F "file=@$GITLEAKS_REPORT" \
                            -F "active=true" \
                            -F "verified=true"
                        ''',
                        returnStatus: true, env: ['DD_API_KEY': DD_API_KEY, 'DD_ENGAGEMENT_ID': DD_ENGAGEMENT_ID, 'SCAN_DATE': SCAN_DATE, 'GITLEAKS_REPORT': GITLEAKS_REPORT]
                    )
                }
            }
        }

        stage('Security Gate - Bandit') {
            steps {
                script {
                    if (fileExists(BANDIT_REPORT)) {
                        def report = readJSON file: BANDIT_REPORT
                        
                        def highCount = report.results.count { it.issue_severity == "HIGH" }
                        
                        echo "Bandit Security Gate:"
                        echo "  - HIGH (críticas): ${highCount}"
                        echo "  - MEDIUM: ${report.results.count { it.issue_severity == "MEDIUM" }}"
                        echo "  - LOW: ${report.results.count { it.issue_severity == "LOW" }}"
                        
                        if (highCount > 0) {
                            error("✗ SECURITY GATE FALLIDO: ${highCount} vulnerabilidades HIGH encontradas")
                        } else {
                            echo "✓ Security Gate: PASSED"
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
                        // script shell
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
                        
                        //Leer resultados
                        def output = readFile('metrics_output.txt')
                        def critical = (output =~ /CRITICAL=(\d+)/)[0][1].toInteger()
                        def high     = (output =~ /HIGH=(\d+)/)[0][1].toInteger()
                        
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