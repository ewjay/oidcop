import sbt._
import Keys._
import play.Project._

object ApplicationBuild extends Build {

  val appName         = "oidcop"
  val appVersion      = "1.0-SNAPSHOT"

  val appDependencies = Seq(
    // Add your project dependencies here,
    jdbc,
    anorm,
    "mysql"  %  "mysql-connector-java" % "5.1.18",
    "jp.t2v" %% "play2.auth"           % "0.9",
    "jp.t2v" %% "play2.auth.test"      % "0.9"     % "test"

  )


  val main = play.Project(appName, appVersion, appDependencies).settings(
    // Add your own project settings here
  )

}
