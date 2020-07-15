@Library('jenkins_lib')_
pipeline {
  agent any
 
  environment {
    // Define global environment variables in this section
    ARTIFACT_SRC1 = 'dist'
    ARTIFACT_SRC2 = 'target/releases/'
    ARTIFACT_DEST1 = 'ggn-dev-rpms/opendistro-security'
    ARTIFACT_DEST2 = 'ggn-archive/opendistro-security'
    SLACK_CHANNEL = 'jenkins-cdap-alerts'
    CHECKSTYLE_FILE = 'target/javastyle-result.xml'
    UNIT_RESULT = 'target/surefire-reports/*.xml'
    COBERTURA_REPORT = 'target/site/cobertura/coverage.xml'
    ALLURE_REPORT = 'allure-report/'
    HTML_REPORT = 'index.html'
    ARCHIVE_RPM_PATH = "dist/*.rpm"
    ARCHIVE_ZIP_PATH = "dist/*.zip"
    SONAR_PATH = './'
 
  }
  stages {
    stage("Define Release version"){
      steps {
      script {
       //Global Lib for Environment Versions Definition
        versionDefine()
        }
      }
    }
    stage("Compile, Build and Test") {
      steps {
      script {
        echo "Running Test"
        sh 'mvn clean test'
        echo "Running Build"
        sh 'mvn clean package -Padvanced -DskipTests'
        echo "Running Cobertura"
        sh 'mvn cobertura:cobertura -Dcobertura.report.format=xml'
        }
      }
    }
    stage('SonarQube analysis') {
    steps {
      script {
        //Global Lib for Sonarqube runnner JAVA
        sonarqube(env.SONAR_PATH)
      }
    }
    }
    // stage('SonarQube analysis') {
    //     steps {
    //         script {
    //         timeout(time: 1, unit: 'HOURS') {
    //         def qg = waitForQualityGate()  
    //         if (qg.status != 'OK') {
    //         error "Pipeline aborted due to quality gate failure: ${qg.status}"
    //         }
    //         }
    //         }
    //         }
    //     }
  
    stage("RPM Build"){
    steps {
      script {
          echo "Running RPM Build"
          sh 'chmod +x gradlew'
          sh 'artifact_zip=`ls $(pwd)/target/releases/opendistro_security-*.zip | grep -v admin-standalone` && ./gradlew build buildRpm --no-daemon -ParchivePath=$artifact_zip -Dbuild.snapshot=false'
      }
    }
    }

    stage("ARTIFACTS PUSH"){
    steps{
    script{
            //Global Lib for RPM Push
            //rpm_push(<env.buildType No need to change>, <dist is default pls specify RPM file path, <artifactory target path>) ie.        
            rpm_push(env.buildType, env.ARTIFACT_SRC1, env.ARTIFACT_DEST1)
            tar_push(env.buildType, env.ARTIFACT_SRC2, env.ARTIFACT_DEST2)

    }}}

stage("Deploy and Auto-test"){  //This stage contain Example deployment method/Ansible playbook Trigger
    steps{
        script {
   if  (buildType == 'master'|| buildType ==~ 'PR-.*'|| buildType == 'release' ) {
        echo "placeholder for deploy and auto test"
        }
        }
    }}
}

  post {
       always {
          reports_alerts(env.CHECKSTYLE_FILE, env.UNIT_RESULT, env.COBERTURA_REPORT, env.ALLURE_REPORT, env.HTML_REPORT)
          //Global Lib for Reports publishing
 
          postBuild(env.ARCHIVE_RPM_PATH)
          postBuild(env.ARCHIVE_ZIP_PATH)
         //Global Lib for post build actions eg: artifacts archive
 
          slackalert(env.SLACK_CHANNEL)
         //Global Lib for slack alerts
      }
    }
}