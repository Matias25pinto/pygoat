pipeline{
    agent any

    stages{
        stage('bandit-test'){
            agent{
                docker{
                    image 'python:3.11-alpine'
                }
            }
            steps {
                script{
                    sh 'pip install bandit'
                    sh 'bandit --version'
                    sh 'bandit -r .'
                }
            }
        }

    }
}