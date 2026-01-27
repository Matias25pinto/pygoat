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
                    git checkout defect-dojo
                '''
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
                            --report-path gitleaks-report.json \
                            --no-git
                        ''',
                        returnStatus: true
                    )

                    archiveArtifacts artifacts: 'gitleaks-report.json',
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

        stage('DefectDojo - Auto Product & Engagement') {
            agent {
                docker {
                    image 'python:3.11-slim'
                    args '--network cicd-net'
                }
            }
            steps {
                withCredentials([string(credentialsId: 'defectdojo-api-key', variable: 'DD_API_KEY')]) {
                    sh '''
                        apt-get update -qq && apt-get install -y -qq curl jq

                        echo " Buscando Product..."
                        PRODUCT_JSON=$(curl -s -H "Authorization: Token $DD_API_KEY" \
                            "$DEFECTDOJO_URL/api/v2/products/?name=$PRODUCT_NAME")

                        PRODUCT_ID=$(echo "$PRODUCT_JSON" | jq -r '.results[0].id // empty')

                        if [ -z "$PRODUCT_ID" ]; then
                            echo " Creando Product..."
                            PRODUCT_ID=$(curl -s -X POST "$DEFECTDOJO_URL/api/v2/products/" \
                                -H "Authorization: Token $DD_API_KEY" \
                                -H "Content-Type: application/json" \
                                -d "{
                                \\"name\\": \\"$PRODUCT_NAME\\",
                                \\"description\\": \\"Auto-created from Jenkins\\",
                                \\"prod_type\\": 1
                            }" | jq -r '.id')
                        fi

                        echo " Product ID: $PRODUCT_ID"

                        echo " Buscando Engagement..."
                        ENG_JSON=$(curl -s -H "Authorization: Token $DD_API_KEY" \
                            "$DEFECTDOJO_URL/api/v2/engagements/?name=$ENGAGEMENT_NAME&product=$PRODUCT_ID")

                        ENGAGEMENT_ID=$(echo "$ENG_JSON" | jq -r '.results[0].id // empty')

                        if [ -z "$ENGAGEMENT_ID" ]; then
                            echo " Creando Engagement..."
                            ENGAGEMENT_ID=$(curl -s -X POST "$DEFECTDOJO_URL/api/v2/engagements/" \
                                -H "Authorization: Token $DD_API_KEY" \
                                -H "Content-Type: application/json" \
                                -d "{
                                \\"name\\": \\"$ENGAGEMENT_NAME\\",
                                \\"product\\": $PRODUCT_ID,
                                \\"status\\": \\"In Progress\\",
                                \\"engagement_type\\": \\"CI/CD\\"
                            }" | jq -r '.id')
                        fi

                        echo " Engagement ID: $ENGAGEMENT_ID"

                        echo "PRODUCT_ID=$PRODUCT_ID" > defectdojo.env
                        echo "ENGAGEMENT_ID=$ENGAGEMENT_ID" >> defectdojo.env
                    '''

                    stash name: 'defectdojo-ids', includes: 'defectdojo.env'
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