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
                    git checkout secrets-scan-gitleaks
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
            agent any
            steps {
                script {
                    echo "SCA - Dependency-Track"
                }
            }
        }

        stage('Security Gate - Dependency-Track') {
            agent any
            steps {
                script {
                    echo "Security Gate - Dependency-Track"
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