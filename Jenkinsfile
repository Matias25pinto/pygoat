pipeline {
    agent any

    stages {

        stage('Checkout') {
            steps {
                echo "Obteniendo el código desde GitHub..."
                sh '''
                    rm -rf pygoat || true
                    git clone https://github.com/Matias25pinto/pygoat.git pygoat
                    cd pygoat
                    git checkout ejercicio-2
                '''
                // Stash para compartir el código entre stages con diferentes agentes
                stash name: 'pygoat-code', includes: 'pygoat/**'
            }
        }
        stage('Análisis de Seguridad') {
            parallel {
                stage('SAST - Bandit') {
                    agent {
                        docker {
                            image 'python:3.11-slim'
                            args '-u root'
                        }
                    }
                    steps {
                        script {
                            // Recuperar el código stasheado
                            unstash 'pygoat-code'
                            
                            sh 'apt-get update && apt-get install -qq -y git'
                            sh 'git config --global --add safe.directory $WORKSPACE/pygoat'
                            sh 'pip install -q bandit'
                            
                            // Eliminar archivo anterior si existe
                            sh 'rm -f reporte_bandit.json || true'
                            
                            // Ejecutar Bandit capturando el exit code
                            def banditExitCode = sh(script: '''
                                cd pygoat
                                bandit -r . -f json -o ../reporte_bandit.json
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
                            sh 'test -f reporte_bandit.json && echo "Archivo reporte_bandit.json creado" || echo "Archivo no existe, creando vacío..."'
                            sh 'test -f reporte_bandit.json || echo "{}" > reporte_bandit.json'
                            sh 'ls -la reporte_bandit.json'
                        }
                        // Archivar resultados
                        archiveArtifacts artifacts: 'reporte_bandit.json', fingerprint: true, allowEmptyArchive: true
                    }
                    
                    post {
                        always {
                            script {
                                if (fileExists('reporte_bandit.json')) {
                                    echo "Resultados de Bandit disponibles para análisis"
                                }
                            }
                        }
                    }
                }

                stage('SCA - Dependency-Track') {
                    agent {
                        docker {
                            image 'python:3.11-slim'
                            args '-u root --network cicd-net'
                        }
                    }
                    environment {
                        DTRACK_URL = 'http://dtrack-api:8080'
                        DTRACK_API_KEY = credentials('dependency-track-api-key')
                        PROJECT_NAME = 'pygoat'
                        PROJECT_VERSION = 'ejercicio-2'
                    }
                    steps {
                        script {
                            unstash 'pygoat-code'

                            sh 'apt-get update && apt-get install -qq -y git curl'
                            sh 'pip install -q cyclonedx-bom'

                            // Generar SBOM desde requirements.txt
                            sh '''
                                cd pygoat
                                cyclonedx-py requirements requirements.txt -o ../bom.json
                            '''

                            // Subir SBOM a Dependency-Track
                            def uploadExitCode = sh(script: '''
                                curl -s -X POST "$DTRACK_URL/api/v1/bom" \
                                -H "X-Api-Key: $DTRACK_API_KEY" \
                                -F "projectName=$PROJECT_NAME" \
                                -F "projectVersion=$PROJECT_VERSION" \
                                -F "autoCreate=true" \
                                -F "bom=@bom.json"
                            ''', returnStatus: true)
                            
                            echo "Curl exit code: ${uploadExitCode}"
                            
                            if (uploadExitCode != 0) {
                                unstable(message: "No se pudo subir SBOM a Dependency-Track")
                                echo "Dependency-Track podría no estar disponible"
                            }
                        }

                        // Archivar resultados
                        archiveArtifacts artifacts: 'bom.json', fingerprint: true, allowEmptyArchive: true
                    }

                    post {
                        always {
                            script {
                                if (fileExists('bom.json')) {
                                    echo "Resultados de Dependency-Track disponibles para análisis"
                                }
                            }
                        }
                    }
                }
            }
        }
        stage('Gates y Escaneo de Secretos') {
            parallel {
                // stage('Security Gate - Bandit') {
                //     agent any
                //     steps {
                //         script {
                //             echo "Verificando security gate para Bandit..."
                            
                //             if (fileExists('reporte_bandit.json')) {
                //                 // Leer el archivo JSON y parsearlo manualmente
                //                 def jsonContent = readFile('reporte_bandit.json').trim()
                                
                //                 // Si el archivo está vacío o solo tiene {}
                //                 if (jsonContent == "{}" || jsonContent == "") {
                //                     echo "No hay hallazgos de Bandit"
                //                 } else {
                //                     // Contar vulnerabilidades usando grep/sed (alternativa simple)
                //                     def criticalCount = sh(script: '''
                //                         grep -c '"issue_severity": "CRITICAL"' reporte_bandit.json || true
                //                     ''', returnStdout: true).trim().toInteger()
                                    
                //                     def highCount = sh(script: '''
                //                         grep -c '"issue_severity": "HIGH"' reporte_bandit.json || true
                //                     ''', returnStdout: true).trim().toInteger()
                                    
                //                     echo "Resumen de Bandit:"
                //                     echo "  - Vulnerabilidades CRÍTICAS: ${criticalCount}"
                //                     echo "  - Vulnerabilidades ALTAS: ${highCount}"
                                    
                //                     if (criticalCount > 0 || highCount > 0) {
                //                         // Mostrar algunas vulnerabilidades encontradas
                //                         sh '''
                //                             echo "VULNERABILIDADES ENCONTRADAS:"
                //                             echo "=== CRÍTICAS ==="
                //                             grep -A2 -B2 '"issue_severity": "CRITICAL"' reporte_bandit.json | head -20 || true
                //                             echo "=== ALTAS ==="
                //                             grep -A2 -B2 '"issue_severity": "HIGH"' reporte_bandit.json | head -20 || true
                //                         '''
                //                         error("SECURITY GATE FALLIDO: Bandit encontró ${criticalCount} críticas y ${highCount} altas")
                //                     } else {
                //                         echo "Security Gate: No se encontraron vulnerabilidades críticas/altas"
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
                            image 'python:3.11-slim'
                            args '-u root --network cicd-net'
                        }
                    }
                    environment {
                        DTRACK_URL = 'http://dtrack-api:8080'
                        PROJECT_NAME = 'pygoat'
                        PROJECT_VERSION = 'ejercicio-2'
                    }
                    steps {
                        script {
                            sh 'apt-get update && apt-get install -y curl jq'
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
                        }
                    }

                    steps {
                        script {
                            unstash 'pygoat-code'

                            def exitCode = sh(
                                script: '''
                                    gitleaks detect \
                                    --source=pygoat \
                                    --report-format json \
                                    --report-path gitleaks-report.json \
                                    --no-git
                                ''',
                                returnStatus: true
                            )

                            // Archivar siempre el reporte
                            archiveArtifacts artifacts: 'gitleaks-report.json', fingerprint: true, allowEmptyArchive: true

                            // Analizar resultado
                            if (exitCode != 0) {
                                unstable("Gitleaks detectó posibles secretos en el repositorio")
                            } else {
                                echo "No se detectaron secretos"
                            }
                        }
                    }

                    post {
                        always {
                            echo "Análisis de secretos finalizado (Gitleaks)"
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