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
                    git checkout sca-dependency-track
                '''
                // Stash para compartir el código entre stages con diferentes agentes
                stash name: 'pygoat-code', includes: 'pygoat/**'
            }
        }

        stage('SAST - Bandit') {
            agent any
            steps {
                script {
                    echo "SAST - Bandit"
                }
            }
        }

        stage('Security Gate - Bandit') {
            agent any
            steps {
                script {
                    echo "Security Gate - Bandit"
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
                PROJECT_VERSION = "ejercicio-2"
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
                PROJECT_VERSION = "ejercicio-2"
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
            agent any
            steps {
                script {
                    echo "Secrets Scan - Gitleaks"
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