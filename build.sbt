import ReleaseTransformations._

ThisBuild / scalaVersion         := "2.13.3"
ThisBuild / organization         := "com.dedipresta"
ThisBuild / organizationName     := "Dedipresta"
ThisBuild / startYear            := Some(2020)
ThisBuild / organizationHomepage := Some(url("https://www.dedipresta.com"))
ThisBuild / scalafmtOnCompile    := true
ThisBuild / scalafixDependencies += "com.nequissimus" %% "sort-imports" % "0.5.0"
ThisBuild / semanticdbEnabled    := true
ThisBuild / semanticdbVersion    := "4.3.20"
ThisBuild / scapegoatVersion     := "1.4.5"
ThisBuild / crossScalaVersions   := List("2.12.11", "2.13.3")

ThisBuild / developers := List(
  Developer(
    "mprevel",
    "Mathieu Prevel",
    "contact@dedipresta.com",
    url("https://www.dedipresta.com")
  )
)

ThisBuild / homepage          := Some(url("https://github.com/dedipresta/scala-crypto"))
ThisBuild / scmInfo           := Some(ScmInfo(url("https://github.com/dedipresta/scala-crypto"), "git@github.com:dedipresta/scala-crypto.git"))
ThisBuild / publishTo         := Some(if (isSnapshot.value) Opts.resolver.sonatypeSnapshots else Opts.resolver.sonatypeStaging)
ThisBuild / licenses          := List("MIT" -> url("https://opensource.org/licenses/MIT"))
ThisBuild / publishMavenStyle := true
ThisBuild / releaseCrossBuild := true
ThisBuild / releaseProcess := Seq[ReleaseStep](
  checkSnapshotDependencies, // check that there is no SNAPSHOT dependencies
  inquireVersions, // ask user to enter the current and next version
  runClean, // clean
  runTest, // run tests
  setReleaseVersion, // set release version in version.sbt
  commitReleaseVersion, // commit the release version
  tagRelease, // create git tag
  releaseStepCommandAndRemaining("+publishSigned"), // run +publishSigned command to sonatype stage release
  setNextVersion, // set next version in version.sbt
  commitNextVersion, // commit next version
  releaseStepCommand("sonatypeRelease"), // run sonatypeRelease and publish to maven central
  pushChanges // push changes to git
)

lazy val versions = new {
  val scalaTest           = "3.1.2"
  val scalaTestScalaCheck = "3.2.0.0"
  val scalaCheck          = "1.14.3"
}

lazy val scalaTest           = Def.setting("org.scalatest"     %%% "scalatest"       % versions.scalaTest           % Test)
lazy val scalaTestScalaCheck = Def.setting("org.scalatestplus" %%% "scalacheck-1-14" % versions.scalaTestScalaCheck % Test)
lazy val scalaCheck          = Def.setting("org.scalacheck"    %%% "scalacheck"      % versions.scalaCheck          % Test)

lazy val commonLibraryDependencies = Def.setting(scalaTestScalaCheck.value :: scalaCheck.value :: scalaTest.value :: Nil)

lazy val commonLibrarySettings = Seq(
  coverageMinimum       := 95,
  coverageFailOnMinimum := true,
  libraryDependencies   ++= commonLibraryDependencies.value,
  addCompilerPlugin(scalafixSemanticdb)
)

lazy val root = project
  .in(file("."))
  .aggregate(`scala-crypto`.js, `scala-crypto`.jvm)
  .settings(
    skip in publish := true
  )

lazy val `scala-crypto` = (crossProject(JSPlatform, JVMPlatform).crossType(CrossType.Full) in file("."))
  .settings(
    name        := "scala-crypto",
    description := "Algorithm for scala and scala.js",
    commonLibrarySettings,
    addCompilerPlugin(scalafixSemanticdb)
  )
  .jsSettings(coverageEnabled := false)
