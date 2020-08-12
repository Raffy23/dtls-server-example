name := "DTLS-Tests"

version := "0.1"

scalaVersion := "2.13.3"

val bouncyCastleVersion = "1.66"

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcpkix-jdk15on" % bouncyCastleVersion,
  "org.bouncycastle" % "bctls-jdk15on"  % bouncyCastleVersion,
)


