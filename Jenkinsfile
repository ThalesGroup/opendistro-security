@Library('jenkins_lib')_
pipeline {
  agent any
 
  environment {
    // Define global environment variables in this section
    ARTIFACT_SRC1 = 'dist'
    ARTIFACT_DEST1 = 'ggn-dev-rpms/opendistro-security'
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
        sh 'mvn clean package -Padvanced -DskipTests artifact_zip=`ls $(pwd)/target/releases/opendistro_security-*.zip | grep -v admin-standalone`'
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
    stage('SonarQube analysis') {
        steps {
            script {
            timeout(time: 1, unit: 'HOURS') {
            def qg = waitForQualityGate()  
            if (qg.status != 'OK') {
            error "Pipeline aborted due to quality gate failure: ${qg.status}"
            }
            }
            }
            }
        }
  
    stage("RPM Build"){
    steps {
      script {
          sh 'chmod +x gradlew'
          sh './gradlew build buildRpm --no-daemon -ParchivePath=$artifact_zip -Dbuild.snapshot=false'
      }
    }
    }

    stage("RPM PUSH"){
    steps{
    script{
            //Global Lib for RPM Push
            //rpm_push(<env.buildType No need to change>, <dist is default pls specify RPM file path, <artifactory target path>) ie.        
            rpm_push( env.buildType, env.ARTIFACT_SRC1, env.ARTIFACT_DEST1 )
    }}}

stage("Deploy and Auto-test"){  //This stage contain Example deployment method/Ansible playbook Trigger
    steps{
        script {
   if  (buildType == 'master'|| buildType ==~ 'PR-.*'|| buildType == 'release' ) {
        // sh 'ssh -o StrictHostKeyChecking=no siguavus@192.168.133.221 "sudo yum remove -y  customer360*|| true"'
        // sh 'ssh -o StrictHostKeyChecking=no siguavus@192.168.133.221 "sudo rpm -ivh http://artifacts.ggn.in.guavus.com:8081/artifactory/ggn-dev-rpms/jio_spark_jobs/${VERSION}/${REL_ENV}/customer360-provisioner-${VERSION}-${RELEASE}.x86_64.rpm"'
 
        // sh 'ssh -o StrictHostKeyChecking=no siguavus@192.168.133.221 "sudo sh /etc/customer360-provisioner/scripts/get-hdfs-details.sh reflex-platform-jbdl"'
        // sh 'ssh -o StrictHostKeyChecking=no siguavus@192.168.133.221 "cd /etc/customer360-provisioner/ && ansible-playbook -i inventory/jio/hosts playbooks/uapp1/deploy.yml --user siguavus --become --become-method sudo -e \'jio_uapp1_jar_version=${VERSION}\' -e \'jio_uapp1_rel_env=${REL_ENV}\' -e \'jio_uapp1_jar_release=${RELEASE}\'"'
        // sh 'ssh -o StrictHostKeyChecking=no siguavus@192.168.133.221 "cd /etc/customer360-provisioner/ && ansible-playbook -i inventory/jio/hosts playbooks/uapp1/undeploy.yml --user siguavus --become --become-method sudo -e \'jio_uapp1_jar_release=${RELEASE}\'"'
 
 
        // sh 'ssh -o StrictHostKeyChecking=no siguavus@192.168.133.221 "sudo yum remove -y  customer360*|| true"'
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