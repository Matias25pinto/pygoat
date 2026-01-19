pipeline {
    agent any

    stages {

        stage('Checkout') {
            steps {
                echo "Obteniendo el código desde GitHub..."
                sh 'rm -rf pygoat || true'
                sh 'git clone https://github.com/Matias25pinto/pygoat.git pygoat'
                sh 'cd pygoat'
                sh 'git checkout ejercicio-2'
                // Stash para compartir el código entre stages con diferentes agentes
                stash name: 'pygoat-code', includes: 'pygoat/**'
            }
        }

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
                    
                    try {
                        // Ejecutar Bandit en el directorio pygoat
                        sh '''
                                cd pygoat
                                bandit -r . -f json -o ../reporte_bandit.json
                        '''
                    } catch (err) {
                        unstable(message: "Bandit encontró hallazgos de seguridad")
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
                        cyclonedx-py requirements requirements.txt -o ../bom.xml
                    '''

                    // Subir SBOM a Dependency-Track
                    sh '''
                        curl -s -X POST "$DTRACK_URL/api/v1/bom" \
                        -H "X-Api-Key: $DTRACK_API_KEY" \
                        -F "projectName=$PROJECT_NAME" \
                        -F "projectVersion=$PROJECT_VERSION" \
                        -F "autoCreate=true" \
                        -F "bom=@bom.xml"
                    '''
                }

                archiveArtifacts artifacts: 'bom.xml', fingerprint: true
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