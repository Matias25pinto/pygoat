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
                    ''', returnStatus: true)
                    
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
                    ''', returnStatus: true)
                    
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
                        returnStatus: true
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
                        returnStatus: true
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
                        returnStatus: true
                    )
                }
            }
        }

        // stage('Security Gate - Bandit') {
        //     agent {
        //         docker {
        //             image 'ci-python-security:latest'
        //             reuseNode true
        //         }
        //     }
        //     steps {
        //         script {
        //             echo "Verificando security gate para Bandit..."
                    
        //             if (fileExists(BANDIT_REPORT)) {
        //                 def jsonContent = readFile(BANDIT_REPORT).trim()

        //                 if (jsonContent == "{}" || jsonContent == "") {
        //                     echo "No hay hallazgos de Bandit"
        //                 } else {

        //                     def highCountJq = sh(
        //                         script: '''
        //                             jq '.metrics._totals["SEVERITY.HIGH"] // 0' $BANDIT_REPORT
        //                         ''',
        //                         returnStdout: true
        //                     ).trim().toInteger()
                            
        //                     echo "Resumen de Bandit: "
        //                     echo "  - Vulnerabilidades HIGH (graves): ${highCountJq}"
                            
        //                     if (highCountJq > 0) {
        //                         // Mostrar detalles de las vulnerabilidades HIGH
        //                         sh """
        //                             echo "VULNERABILIDADES HIGH ENCONTRADAS:"
        //                             echo "=== DETALLES ==="
        //                             jq -r '.results[] | select(.issue_severity == "HIGH") | "- \\(.test_id): \\(.issue_text) (línea \\(.line_number))"' ${BANDIT_REPORT} || true
        //                         """
        //                         error("SECURITY GATE FALLIDO: Bandit reportó ${highCountJq} altas")
        //                     } else {
        //                         echo "✅ Security Gate: PASSED"
        //                     }
        //                 }
        //             } else {
        //                 echo "No se encontró reporte de Bandit"
        //             }
        //         }
        //     }
        // }

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
                    withCredentials([string(credentialsId: 'dependency-track-api-key', variable: 'DTRACK_API_KEY')]) {

                        def maxAttempts = 24 
                        def waitSeconds = 5
                        def projectUuid = null

                        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
                            echo "Intento ${attempt}/${maxAttempts}: Buscando proyecto ${PROJECT_NAME}:${PROJECT_VERSION}"

                            def rawResponse = sh(
                                script: '''#!/bin/bash
                                    curl -s \
                                        --max-time 10 \
                                        --connect-timeout 5 \
                                        -w "\\n%{http_code}" \
                                        -H "X-Api-Key: ${DTRACK_API_KEY}" \
                                        "$DTRACK_URL/api/v1/project/lookup?name=$PROJECT_NAME&version=$PROJECT_VERSION"
                                ''',
                                returnStdout: true
                            ).trim()

                            def lines = rawResponse.readLines()
                            def httpCode = lines.last()
                            def body = lines.dropRight(1).join('\n')

                            if (httpCode != "200") {
                                if (attempt < maxAttempts) {
                                    echo "API respondió ${httpCode}, reintentando en ${waitSeconds}s..."
                                    sleep time: waitSeconds, unit: 'SECONDS'
                                    continue
                                }
                                error("No se pudo obtener el proyecto (HTTP ${httpCode})")
                            }

                            writeFile file: 'project.json', text: body

                            projectUuid = sh(
                                script: "jq -r '.uuid // empty' project.json",
                                returnStdout: true
                            ).trim()

                            if (projectUuid) {
                                echo "Proyecto encontrado: UUID=${projectUuid}"
                                break
                            }

                            if (attempt < maxAttempts) {
                                echo "Proyecto aún no disponible, reintentando en ${waitSeconds}s..."
                                sleep time: waitSeconds, unit: 'SECONDS'
                            } else {
                                error("Proyecto no encontrado después de ${maxAttempts} intentos")
                            }
                        }

                        if (!projectUuid) {
                            error("No se pudo obtener el UUID del proyecto en Dependency-Track")
                        }

                        def critical = 0
                        def high = 0
                        def metricsReady = false

                        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
                            echo "Intento ${attempt}/${maxAttempts}: Obteniendo métricas del proyecto"

                            def rawMetrics = sh(
                                script: """#!/bin/bash
                                    curl -s \
                                        --max-time 10 \
                                        --connect-timeout 5 \
                                        -w "\\n%{http_code}" \
                                        -H "X-Api-Key: \${DTRACK_API_KEY}" \
                                        "${DTRACK_URL}/api/v1/metrics/project/${projectUuid}/current"
                                """,
                                returnStdout: true
                            ).trim()

                            def lines = rawMetrics.readLines()
                            def httpCode = lines.last()
                            def body = lines.dropRight(1).join('\n')

                            if (httpCode != "200") {
                                if (attempt < maxAttempts) {
                                    echo "API métricas respondió ${httpCode}, reintentando en ${waitSeconds}s..."
                                    sleep time: waitSeconds, unit: 'SECONDS'
                                    continue
                                }
                                error("No se pudieron obtener métricas (HTTP ${httpCode})")
                            }

                            writeFile file: 'metrics.json', text: body

                            def validMetrics = sh(
                                script: "jq -e 'has(\"critical\") and has(\"high\")' metrics.json",
                                returnStatus: true
                            )

                            if (validMetrics != 0) {
                                if (attempt < maxAttempts) {
                                    echo "Métricas aún no calculadas, esperando..."
                                    sleep time: waitSeconds, unit: 'SECONDS'
                                    continue
                                }
                                error("Dependency-Track no entregó métricas válidas")
                            }

                            critical = sh(
                                script: "jq '.critical // 0' metrics.json",
                                returnStdout: true
                            ).trim().toInteger()

                            high = sh(
                                script: "jq '.high // 0' metrics.json",
                                returnStdout: true
                            ).trim().toInteger()

                            echo "Métricas obtenidas: Críticas=${critical}, Altas=${high}"
                            metricsReady = true
                            break
                        }

                        if (!metricsReady) {
                            error("No se pudieron obtener métricas válidas después de ${maxAttempts} intentos")
                        }

                        
                        echo "Métricas Dependency-Track finales:"
                        echo "  - Críticas: ${critical}"
                        echo "  - Altas: ${high}"

                        if (critical > 0 || high > 0) {
                            error("SECURITY GATE FALLIDO: Dependency-Track reportó ${critical} críticas y ${high} altas")
                        } else {
                            echo "✅ Security Gate PASSED: No hay vulnerabilidades críticas ni altas"
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